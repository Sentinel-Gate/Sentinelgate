// Package httpgw provides the HTTP Gateway forward proxy handler.
// It intercepts HTTP requests, normalizes them to CanonicalAction,
// runs the canonical security chain (policy, outbound, scan),
// and forwards allowed requests to their original destination.
package httpgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

// maxScanBodySize is the maximum response body size to buffer for scanning.
// Responses larger than this are streamed directly without scanning.
const maxScanBodySize = 64 * 1024 // 64KB

// hopByHopHeaders lists headers that must be removed when forwarding requests.
// These headers are meaningful only for a single transport-level connection
// and must not be forwarded by proxies (RFC 2616 Section 13.5.1).
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// Handler is the HTTP Gateway handler supporting both forward and reverse proxy modes.
// It normalizes incoming HTTP requests to CanonicalAction, runs them through
// the ActionInterceptor security chain, and forwards allowed requests upstream.
// In reverse proxy mode, requests matching upstream targets are forwarded to the
// configured upstream after the security chain approves the request.
type Handler struct {
	normalizer      *action.HTTPNormalizer
	chain           action.ActionInterceptor // The canonical security chain
	httpClient      *http.Client             // For forwarding allowed requests
	reverseProxy    *ReverseProxy            // nil = forward proxy only
	websocketProxy  *WebSocketProxy          // nil = no WebSocket support
	responseScanner *action.ResponseScanner  // nil = no response scanning
	scanMode        func() action.ScanMode   // closure reading atomic value
	scanEnabled     func() bool              // closure reading atomic bool
	logger          *slog.Logger
}

// NewHandler creates a new HTTP Gateway handler.
// The chain is the ActionInterceptor that processes the security pipeline
// (policy -> outbound -> response scan -> passthrough).
func NewHandler(chain action.ActionInterceptor, logger *slog.Logger) *Handler {
	return &Handler{
		normalizer: action.NewHTTPNormalizer(),
		chain:      chain,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			// Do not follow redirects automatically -- pass them through to the caller.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			// SSRF protection: custom dialer that blocks connections to private IPs.
			// This prevents forward proxy abuse targeting localhost, cloud metadata,
			// and internal network services. The check happens after DNS resolution
			// and pins to the resolved IP (prevents DNS rebinding).
			Transport: &http.Transport{
				DialContext: safeDialContext(),
			},
		},
		logger: logger,
	}
}

// SetTimeout configures the HTTP client timeout for forwarding requests.
func (h *Handler) SetTimeout(d time.Duration) {
	h.httpClient.Timeout = d
}

// DisableSSRFProtection removes the SSRF-safe dialer from the HTTP client.
// This is intended ONLY for testing and dev mode where forward proxy
// targets may be on localhost.
func (h *Handler) DisableSSRFProtection() {
	h.httpClient.Transport = nil
}

// SetReverseProxy enables reverse proxy mode by attaching a ReverseProxy.
// When set, requests matching upstream targets are forwarded to the configured
// upstream instead of using forward proxy mode.
func (h *Handler) SetReverseProxy(rp *ReverseProxy) {
	h.reverseProxy = rp
}

// SetWebSocketProxy attaches a WebSocketProxy for handling WebSocket upgrade requests.
// When set, requests with Connection: Upgrade and Upgrade: websocket headers
// are routed to the WebSocket proxy after passing through the security chain.
func (h *Handler) SetWebSocketProxy(ws *WebSocketProxy) {
	h.websocketProxy = ws
}

// SetResponseScanner attaches a response scanner for scanning HTTP response bodies
// before returning them to the client. The modeGetter and enabledGetter closures
// provide thread-safe access to the current scan mode and enabled state.
func (h *Handler) SetResponseScanner(scanner *action.ResponseScanner, modeGetter func() action.ScanMode, enabledGetter func() bool) {
	h.responseScanner = scanner
	h.scanMode = modeGetter
	h.scanEnabled = enabledGetter
}

// ServeHTTP handles an incoming HTTP request through the gateway.
// Flow: check reverse proxy -> normalize -> identity from context -> chain -> forward or error.
//
// In reverse proxy mode, if the request path matches an upstream target,
// the Destination is overridden with the actual upstream URL so that
// outbound rules and CEL dest_* variables evaluate against the real target.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Detect WebSocket upgrade and route to WebSocket proxy
	if isWebSocketUpgrade(r) && h.websocketProxy != nil {
		h.handleWebSocketUpgrade(w, r)
		return
	}

	// Check for reverse proxy target match first
	var rpTarget *UpstreamTarget
	if h.reverseProxy != nil {
		rpTarget = h.reverseProxy.Match(r.URL.Path)
	}

	// 1. Normalize the incoming request to CanonicalAction
	ca, err := h.normalizer.Normalize(r.Context(), r)
	if err != nil {
		h.logger.Error("failed to normalize HTTP request", "error", err)
		writeJSONError(w, http.StatusBadGateway, "gateway_error", "", err.Error(), "", "")
		return
	}

	// 2. If reverse proxy target matched, override Destination with actual upstream URL
	// so that outbound rules and CEL dest_* variables evaluate against the real target.
	// Also skip outbound checking — the admin explicitly configured this upstream.
	if rpTarget != nil {
		upstreamURL := buildUpstreamURL(rpTarget, r.URL.Path)
		ca.Destination = action.Destination{
			URL:    upstreamURL,
			Domain: extractDomain(rpTarget.Upstream),
			Port:   extractPort(rpTarget.Upstream),
			Scheme: extractScheme(rpTarget.Upstream),
			Path:   extractPath(upstreamURL),
		}
		if ca.Metadata == nil {
			ca.Metadata = make(map[string]interface{})
		}
		ca.Metadata["skip_outbound_check"] = true
	}

	// 3. Read identity from context (set by auth middleware) and apply to CanonicalAction
	if identity, ok := r.Context().Value(ContextKeyIdentity).(*action.ActionIdentity); ok && identity != nil {
		ca.Identity = *identity
	}

	// 4. Run through the ActionInterceptor chain
	_, chainErr := h.chain.Intercept(r.Context(), ca)
	if chainErr != nil {
		h.handleChainError(w, chainErr)
		return
	}

	// 5. Forward the allowed request
	if rpTarget != nil {
		// Reverse proxy mode: forward via ReverseProxy
		h.reverseProxy.Forward(w, r, rpTarget)
	} else {
		// Forward proxy mode: forward to original destination
		h.forwardRequest(w, r, ca)
	}
}

// handleWebSocketUpgrade processes WebSocket upgrade requests through the
// security chain and then delegates to the WebSocket proxy.
func (h *Handler) handleWebSocketUpgrade(w http.ResponseWriter, r *http.Request) {
	// Check for reverse proxy target match
	var rpTarget *UpstreamTarget
	if h.reverseProxy != nil {
		rpTarget = h.reverseProxy.Match(r.URL.Path)
	}

	// Normalize for policy check
	ca, err := h.normalizer.Normalize(r.Context(), r)
	if err != nil {
		h.logger.Error("failed to normalize WebSocket request", "error", err)
		writeJSONError(w, http.StatusBadGateway, "gateway_error", "", err.Error(), "", "")
		return
	}

	// Override destination for reverse proxy targets and skip outbound checking.
	if rpTarget != nil {
		upstreamURL := buildUpstreamURL(rpTarget, r.URL.Path)
		ca.Destination = action.Destination{
			URL:    upstreamURL,
			Domain: extractDomain(rpTarget.Upstream),
			Port:   extractPort(rpTarget.Upstream),
			Scheme: extractScheme(rpTarget.Upstream),
			Path:   extractPath(upstreamURL),
		}
		if ca.Metadata == nil {
			ca.Metadata = make(map[string]interface{})
		}
		ca.Metadata["skip_outbound_check"] = true
	}

	// Apply identity from context
	if identity, ok := r.Context().Value(ContextKeyIdentity).(*action.ActionIdentity); ok && identity != nil {
		ca.Identity = *identity
	}

	// Run security chain (auth/policy check)
	_, chainErr := h.chain.Intercept(r.Context(), ca)
	if chainErr != nil {
		h.handleChainError(w, chainErr)
		return
	}

	// Build the WebSocket destination URL
	destURL := ca.Destination.URL
	if rpTarget != nil {
		destURL = buildUpstreamURL(rpTarget, r.URL.Path)
	}
	// Replace http/https with ws/wss
	destURL = strings.Replace(destURL, "https://", "wss://", 1)
	destURL = strings.Replace(destURL, "http://", "ws://", 1)

	_ = h.websocketProxy.Proxy(w, r, destURL)
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade request.
// Per RFC 6455, this requires Connection: Upgrade and Upgrade: websocket
// headers (case-insensitive).
func isWebSocketUpgrade(r *http.Request) bool {
	connection := r.Header.Get("Connection")
	upgrade := r.Header.Get("Upgrade")
	return strings.EqualFold(connection, "upgrade") && strings.EqualFold(upgrade, "websocket")
}

// Routes returns the handler itself (Handler implements http.Handler via ServeHTTP).
func (h *Handler) Routes() http.Handler {
	return h
}

// handleChainError writes the appropriate HTTP error response based on chain error type.
func (h *Handler) handleChainError(w http.ResponseWriter, err error) {
	// Check for PolicyDenyError
	var policyErr *proxy.PolicyDenyError
	if errors.As(err, &policyErr) {
		h.logger.Info("HTTP request denied by policy",
			"rule_id", policyErr.RuleID,
			"rule_name", policyErr.RuleName,
			"reason", policyErr.Reason,
		)
		writeJSONError(w, http.StatusForbidden, "policy_denied", policyErr.RuleName, policyErr.Reason, policyErr.HelpURL, policyErr.HelpText)
		return
	}

	// Check for ErrPolicyDenied sentinel (wrapped errors from PolicyActionInterceptor)
	if errors.Is(err, proxy.ErrPolicyDenied) {
		h.logger.Info("HTTP request denied by policy", "error", err.Error())
		writeJSONError(w, http.StatusForbidden, "policy_denied", "", err.Error(), "", "")
		return
	}

	// Check for OutboundDenyError
	var outboundErr *action.OutboundDenyError
	if errors.As(err, &outboundErr) {
		h.logger.Info("HTTP request blocked by outbound rule",
			"rule", outboundErr.RuleName,
			"domain", outboundErr.Domain,
			"reason", outboundErr.Reason,
		)
		writeJSONError(w, http.StatusForbidden, "outbound_blocked", outboundErr.RuleName, outboundErr.Reason, outboundErr.HelpURL, outboundErr.HelpText)
		return
	}

	// Check for ErrOutboundBlocked sentinel
	if errors.Is(err, action.ErrOutboundBlocked) {
		h.logger.Info("HTTP request blocked by outbound control", "error", err.Error())
		writeJSONError(w, http.StatusForbidden, "outbound_blocked", "", err.Error(), "", "")
		return
	}

	// Other errors -> 502
	h.logger.Error("HTTP gateway chain error", "error", err)
	writeJSONError(w, http.StatusBadGateway, "gateway_error", "", "internal gateway error", "", "")
}

// forwardRequest forwards the original HTTP request to its destination
// and copies the response back to the caller.
func (h *Handler) forwardRequest(w http.ResponseWriter, r *http.Request, ca *action.CanonicalAction) {
	// Build the outbound request from the original
	destURL := ca.Destination.URL
	if destURL == "" {
		h.logger.Error("no destination URL in canonical action")
		writeJSONError(w, http.StatusBadGateway, "gateway_error", "", "no destination URL", "", "")
		return
	}

	// Retrieve the original request (body was restored by normalizer)
	origReq, ok := ca.OriginalMessage.(*http.Request)
	if !ok {
		h.logger.Error("original message is not *http.Request")
		writeJSONError(w, http.StatusBadGateway, "gateway_error", "", "internal error", "", "")
		return
	}

	outReq, err := http.NewRequestWithContext(r.Context(), origReq.Method, destURL, origReq.Body)
	if err != nil {
		h.logger.Error("failed to create outbound request", "error", err, "url", destURL)
		writeJSONError(w, http.StatusBadGateway, "gateway_error", "", "failed to create outbound request", "", "")
		return
	}

	// Copy headers from original request
	for key, values := range origReq.Header {
		for _, v := range values {
			outReq.Header.Add(key, v)
		}
	}

	// Remove hop-by-hop headers
	for _, h := range hopByHopHeaders {
		outReq.Header.Del(h)
	}

	// Add forwarding headers
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	if prior := outReq.Header.Get("X-Forwarded-For"); prior != "" {
		outReq.Header.Set("X-Forwarded-For", prior+", "+clientIP)
	} else {
		outReq.Header.Set("X-Forwarded-For", clientIP)
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	outReq.Header.Set("X-Forwarded-Proto", scheme)
	outReq.Header.Set("X-Forwarded-Host", r.Host)

	// Forward the request
	resp, err := h.httpClient.Do(outReq)
	if err != nil {
		h.logger.Error("failed to forward request", "error", err, "url", destURL)
		writeJSONError(w, http.StatusBadGateway, "gateway_error", "", "upstream unreachable", "", "")
		return
	}
	defer resp.Body.Close()

	// Scan response body for prompt injection if scanner is configured
	if h.responseScanner != nil && h.scanEnabled != nil && h.scanEnabled() {
		if isTextContentType(resp.Header.Get("Content-Type")) {
			h.scanHTTPResponse(w, resp)
			// scanHTTPResponse writes the response whether blocked or not
			return
		}
	}

	// Copy response headers
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}

	// Copy response status and body
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.logger.Debug("error copying response body", "error", err)
	}
}

// writeJSONError writes a structured JSON error response.
func writeJSONError(w http.ResponseWriter, status int, errorType, rule, reason, helpURL, helpText string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := map[string]interface{}{
		"error": errorType,
	}
	if rule != "" {
		resp["rule"] = rule
	}
	if reason != "" {
		resp["reason"] = reason
	}
	if helpURL != "" {
		resp["help_url"] = helpURL
	}
	if helpText != "" {
		resp["help_text"] = helpText
	}
	if errorType == "gateway_error" {
		resp["message"] = reason
		delete(resp, "reason")
	}

	_ = json.NewEncoder(w).Encode(resp)
}

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ContextKeyIdentity is the context key for the authenticated identity.
	ContextKeyIdentity contextKey = "httpgw_identity"
	// ContextKeyAPIKey is the context key for the raw API key.
	ContextKeyAPIKey contextKey = "httpgw_api_key"
)

// extractDomain extracts the hostname (without port) from a URL string.
func extractDomain(rawURL string) string {
	// Remove scheme
	u := rawURL
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	// Remove path
	if idx := strings.Index(u, "/"); idx != -1 {
		u = u[:idx]
	}
	// Remove port
	if idx := strings.LastIndex(u, ":"); idx != -1 {
		// Handle IPv6
		if !strings.Contains(u, "]") || strings.LastIndex(u, ":") > strings.LastIndex(u, "]") {
			u = u[:idx]
		}
	}
	return u
}

// extractPort extracts the port number from a URL string.
// Returns default port (443 for https, 80 for http) if no explicit port.
func extractPort(rawURL string) int {
	// Remove scheme
	u := rawURL
	scheme := "http"
	if idx := strings.Index(u, "://"); idx != -1 {
		scheme = u[:idx]
		u = u[idx+3:]
	}
	// Remove path
	if idx := strings.Index(u, "/"); idx != -1 {
		u = u[:idx]
	}
	// Extract port
	if idx := strings.LastIndex(u, ":"); idx != -1 {
		portStr := u[idx+1:]
		port := 0
		for _, c := range portStr {
			if c >= '0' && c <= '9' {
				port = port*10 + int(c-'0')
			} else {
				break
			}
		}
		if port > 0 {
			return port
		}
	}
	// Default ports
	if scheme == "https" {
		return 443
	}
	return 80
}

// extractScheme extracts the scheme from a URL string, defaulting to "http".
func extractScheme(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx != -1 {
		return rawURL[:idx]
	}
	return "http"
}

// scanHTTPResponse buffers the response body, scans it for prompt injection,
// and either blocks (enforce mode) or writes the response (monitor/no detection).
// Returns true if the response was blocked (caller should return immediately).
func (h *Handler) scanHTTPResponse(w http.ResponseWriter, resp *http.Response) bool {
	// Read body up to maxScanBodySize
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxScanBodySize+1))
	if err != nil {
		h.logger.Error("failed to read response body for scanning", "error", err)
		// On error, forward without scanning
		h.writeBufferedResponse(w, resp, bodyBytes)
		return false
	}

	// If body exceeds limit, skip scanning and stream
	if len(bodyBytes) > maxScanBodySize {
		h.writeBufferedResponse(w, resp, bodyBytes)
		// Copy remaining body
		if _, err := io.Copy(w, resp.Body); err != nil {
			h.logger.Debug("error copying remaining response body", "error", err)
		}
		return false
	}

	// Scan the body
	scanResult := h.responseScanner.Scan(string(bodyBytes))
	if !scanResult.Detected {
		h.writeBufferedResponse(w, resp, bodyBytes)
		return false
	}

	// Build pattern names for logging
	patternNames := make([]string, 0, len(scanResult.Findings))
	for _, f := range scanResult.Findings {
		patternNames = append(patternNames, f.PatternName)
	}

	mode := h.scanMode()
	h.logger.Warn("HTTP response scanning: prompt injection detected",
		"mode", string(mode),
		"findings_count", len(scanResult.Findings),
		"pattern_names", strings.Join(patternNames, ","),
	)

	if mode == action.ScanModeEnforce {
		writeJSONError(w, http.StatusForbidden, "response_blocked", "",
			"response content blocked by scanning", "", "")
		return true
	}

	// Monitor mode: log and forward
	h.writeBufferedResponse(w, resp, bodyBytes)
	return false
}

// writeBufferedResponse writes a buffered response (headers + body) to the client.
func (h *Handler) writeBufferedResponse(w http.ResponseWriter, resp *http.Response, body []byte) {
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, bytes.NewReader(body)); err != nil {
		h.logger.Debug("error writing buffered response", "error", err)
	}
}

// isTextContentType returns true if the Content-Type is text-based and worth scanning.
func isTextContentType(ct string) bool {
	// Strip charset and other parameters
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = ct[:idx]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))

	if strings.HasPrefix(ct, "text/") {
		return true
	}
	switch ct {
	case "application/json", "application/xml", "application/javascript",
		"application/xhtml+xml", "application/x-www-form-urlencoded":
		return true
	}
	return false
}

// extractPath extracts the path component from a full URL string.
func extractPath(rawURL string) string {
	// Remove scheme
	u := rawURL
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	// Find path start
	if idx := strings.Index(u, "/"); idx != -1 {
		// Remove query string if present
		path := u[idx:]
		if qIdx := strings.Index(path, "?"); qIdx != -1 {
			path = path[:qIdx]
		}
		return path
	}
	return "/"
}
