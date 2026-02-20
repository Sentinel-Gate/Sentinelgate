// Package httpgw provides the HTTP Gateway handler including reverse proxy support.
// The reverse proxy routes incoming requests to configured upstream targets
// based on path prefix matching, running the canonical security chain before forwarding.
package httpgw

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

// UpstreamTarget represents a configured reverse proxy upstream target.
// Requests matching the PathPrefix are forwarded to the Upstream URL
// after passing through the security chain.
type UpstreamTarget struct {
	// ID uniquely identifies this target.
	ID string
	// Name is the human-readable display name.
	Name string
	// PathPrefix is the URL path prefix to match (e.g., "/api/openai/").
	PathPrefix string
	// Upstream is the target URL base (e.g., "https://api.openai.com").
	Upstream string
	// StripPrefix controls whether PathPrefix is stripped before forwarding.
	StripPrefix bool
	// Headers are additional headers to inject into proxied requests.
	Headers map[string]string
	// Enabled controls whether this target is active.
	Enabled bool
}

// ReverseProxy manages upstream targets and forwards requests to them.
// It uses an atomic pointer for lock-free reads of the target list,
// matching the pattern used by OutboundInterceptor.SetRules.
type ReverseProxy struct {
	targets         atomic.Pointer[[]UpstreamTarget]
	client          *http.Client
	responseScanner *action.ResponseScanner
	scanMode        func() action.ScanMode
	scanEnabled     func() bool
	logger          *slog.Logger
}

// NewReverseProxy creates a new ReverseProxy with sensible HTTP client defaults.
func NewReverseProxy(logger *slog.Logger) *ReverseProxy {
	rp := &ReverseProxy{
		client: &http.Client{
			Timeout: 30 * time.Second,
			// Do not follow redirects -- pass them through to the caller.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger: logger,
	}
	// Initialize with empty target list.
	empty := make([]UpstreamTarget, 0)
	rp.targets.Store(&empty)
	return rp
}

// SetTargets stores the upstream targets via atomic pointer for lock-free reads.
func (rp *ReverseProxy) SetTargets(targets []UpstreamTarget) {
	rp.targets.Store(&targets)
}

// Targets returns a copy of the current upstream targets.
// Thread-safe for concurrent access via atomic pointer.
func (rp *ReverseProxy) Targets() []UpstreamTarget {
	ptr := rp.targets.Load()
	if ptr == nil {
		return nil
	}
	orig := *ptr
	result := make([]UpstreamTarget, len(orig))
	copy(result, orig)
	return result
}

// SetTimeout updates the HTTP client timeout for upstream requests.
func (rp *ReverseProxy) SetTimeout(d time.Duration) {
	rp.client.Timeout = d
}

// SetResponseScanner attaches a response scanner for scanning reverse proxy
// response bodies before returning them to the client.
func (rp *ReverseProxy) SetResponseScanner(scanner *action.ResponseScanner, modeGetter func() action.ScanMode, enabledGetter func() bool) {
	rp.responseScanner = scanner
	rp.scanMode = modeGetter
	rp.scanEnabled = enabledGetter
}

// Match finds the most specific (longest PathPrefix) matching enabled target
// for the given path. Returns nil if no target matches.
func (rp *ReverseProxy) Match(path string) *UpstreamTarget {
	targetsPtr := rp.targets.Load()
	if targetsPtr == nil {
		return nil
	}
	targets := *targetsPtr

	var best *UpstreamTarget
	bestLen := 0

	for i := range targets {
		t := &targets[i]
		if !t.Enabled {
			continue
		}
		if strings.HasPrefix(path, t.PathPrefix) && len(t.PathPrefix) > bestLen {
			best = t
			bestLen = len(t.PathPrefix)
		}
	}

	return best
}

// Forward sends the request to the upstream target and copies the response
// back to the client. On error, it returns a 502 Bad Gateway JSON response.
func (rp *ReverseProxy) Forward(w http.ResponseWriter, r *http.Request, target *UpstreamTarget) {
	// Build the target URL
	path := r.URL.Path
	if target.StripPrefix {
		path = strings.TrimPrefix(path, target.PathPrefix)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
	}

	upstreamURL := strings.TrimRight(target.Upstream, "/") + path
	if r.URL.RawQuery != "" {
		upstreamURL += "?" + r.URL.RawQuery
	}

	// Create outbound request with original method and body
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		rp.logger.Error("failed to create reverse proxy request", "error", err, "url", upstreamURL)
		writeJSONError(w, http.StatusBadGateway, "gateway_error", "", "failed to create upstream request", "", "")
		return
	}

	// Copy headers from original request
	for key, values := range r.Header {
		for _, v := range values {
			outReq.Header.Add(key, v)
		}
	}

	// Remove hop-by-hop headers
	for _, h := range hopByHopHeaders {
		outReq.Header.Del(h)
	}

	// Inject target-configured headers (overwrite existing)
	for key, value := range target.Headers {
		outReq.Header.Set(key, value)
	}

	// Add X-Forwarded-* headers
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

	// Execute the request
	resp, err := rp.client.Do(outReq)
	if err != nil {
		rp.logger.Error("reverse proxy upstream error", "error", err, "target", target.Name, "url", upstreamURL)
		writeJSONError(w, http.StatusBadGateway, "gateway_error", "", "upstream unreachable", "", "")
		return
	}
	defer resp.Body.Close()

	// Scan response body for prompt injection if scanner is configured
	if rp.responseScanner != nil && rp.scanEnabled != nil && rp.scanEnabled() {
		if isTextContentType(resp.Header.Get("Content-Type")) {
			rp.scanRPResponse(w, resp)
			// scanRPResponse writes the response whether blocked or not
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
		rp.logger.Debug("error copying reverse proxy response body", "error", err)
	}
}

// scanRPResponse buffers and scans the reverse proxy response body for prompt injection.
// Returns true if the response was blocked (caller should return immediately).
func (rp *ReverseProxy) scanRPResponse(w http.ResponseWriter, resp *http.Response) bool {
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxScanBodySize+1))
	if err != nil {
		rp.logger.Error("failed to read reverse proxy response for scanning", "error", err)
		rp.writeBufferedResponse(w, resp, bodyBytes)
		return false
	}

	if len(bodyBytes) > maxScanBodySize {
		rp.writeBufferedResponse(w, resp, bodyBytes)
		if _, err := io.Copy(w, resp.Body); err != nil {
			rp.logger.Debug("error copying remaining response body", "error", err)
		}
		return false
	}

	scanResult := rp.responseScanner.Scan(string(bodyBytes))
	if !scanResult.Detected {
		rp.writeBufferedResponse(w, resp, bodyBytes)
		return false
	}

	patternNames := make([]string, 0, len(scanResult.Findings))
	for _, f := range scanResult.Findings {
		patternNames = append(patternNames, f.PatternName)
	}

	mode := rp.scanMode()
	rp.logger.Warn("reverse proxy response scanning: prompt injection detected",
		"mode", string(mode),
		"findings_count", len(scanResult.Findings),
		"pattern_names", strings.Join(patternNames, ","),
	)

	if mode == action.ScanModeEnforce {
		writeJSONError(w, http.StatusForbidden, "response_blocked", "",
			"response content blocked by scanning", "", "")
		return true
	}

	rp.writeBufferedResponse(w, resp, bodyBytes)
	return false
}

// writeBufferedResponse writes a buffered response to the client.
func (rp *ReverseProxy) writeBufferedResponse(w http.ResponseWriter, resp *http.Response, body []byte) {
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, bytes.NewReader(body)); err != nil {
		rp.logger.Debug("error writing buffered response", "error", err)
	}
}

// buildUpstreamURL constructs the full upstream URL for a target and path.
// This is used by the handler to populate Destination in CanonicalAction.
func buildUpstreamURL(target *UpstreamTarget, path string) string {
	forwardPath := path
	if target.StripPrefix {
		forwardPath = strings.TrimPrefix(forwardPath, target.PathPrefix)
		if !strings.HasPrefix(forwardPath, "/") {
			forwardPath = "/" + forwardPath
		}
	}
	return strings.TrimRight(target.Upstream, "/") + forwardPath
}
