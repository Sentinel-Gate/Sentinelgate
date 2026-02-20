package httpgw

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TLSInspectorConfig holds configuration for the TLS inspector.
type TLSInspectorConfig struct {
	// Enabled controls whether TLS inspection is active (default false).
	Enabled bool
	// BypassList contains domain patterns to never inspect.
	// Supports exact match (e.g. "example.com") and glob patterns (e.g. "*.google.com").
	BypassList []string
	// CertCache provides per-domain TLS certificates signed by the SentinelGate CA.
	CertCache *CertCache
	// Handler is the HTTP handler (auth + gateway handler) to serve decrypted requests through.
	Handler http.Handler
	// Logger for TLS inspection events.
	Logger *slog.Logger
}

// ConnectFilter is called before establishing CONNECT tunnels.
// It receives the target domain and port. If it returns a non-nil error,
// the tunnel is refused with 403 Forbidden. This enables outbound rule
// enforcement even when TLS inspection is disabled — the proxy knows the
// destination from the CONNECT request and can block it.
type ConnectFilter func(domain string, port int) error

// TLSInspector intercepts CONNECT requests for TLS inspection.
// When TLS inspection is enabled and the domain is not bypassed,
// the CONNECT tunnel is hijacked, a TLS handshake is performed
// using a certificate signed by the SentinelGate CA, and the
// decrypted HTTP request is served through the security chain.
//
// When TLS inspection is disabled or the domain is bypassed,
// the CONNECT request is tunneled as a raw TCP relay.
//
// Non-CONNECT requests are passed through to the handler directly.
type TLSInspector struct {
	config        TLSInspectorConfig
	connectFilter ConnectFilter
	bypassSet     map[string]bool
	bypassGlobs   []string
	mu            sync.RWMutex
	logger        *slog.Logger
}

// NewTLSInspector creates a new TLS inspector with the given configuration.
// The bypass list is parsed into exact matches and glob patterns.
func NewTLSInspector(config TLSInspectorConfig) *TLSInspector {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	ti := &TLSInspector{
		config: config,
		logger: logger,
	}

	ti.parseBypassList(config.BypassList)
	return ti
}

// SetConnectFilter sets a filter function called before every CONNECT tunnel.
// This enables outbound rule enforcement on HTTPS destinations even without
// TLS inspection — the domain is visible in the CONNECT request.
func (ti *TLSInspector) SetConnectFilter(f ConnectFilter) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	ti.connectFilter = f
}

// SetBypassList atomically updates the bypass set and glob patterns.
// Thread-safe for concurrent reads during request handling and writes
// from the admin API.
func (ti *TLSInspector) SetBypassList(domains []string) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	ti.parseBypassListLocked(domains)
}

// IsEnabled returns whether TLS inspection is active.
func (ti *TLSInspector) IsEnabled() bool {
	ti.mu.RLock()
	defer ti.mu.RUnlock()
	return ti.config.Enabled
}

// SetEnabled enables or disables TLS inspection at runtime.
// Thread-safe for concurrent reads during request handling and writes
// from the admin API.
func (ti *TLSInspector) SetEnabled(enabled bool) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	ti.config.Enabled = enabled
}

// BypassList returns a copy of the current bypass domain list.
// Thread-safe for concurrent access from admin API.
func (ti *TLSInspector) BypassList() []string {
	ti.mu.RLock()
	defer ti.mu.RUnlock()

	var result []string
	// Reconstruct from bypassSet (exact matches)
	for d := range ti.bypassSet {
		result = append(result, d)
	}
	// Reconstruct from bypassGlobs (prefix with "*.")
	for _, suffix := range ti.bypassGlobs {
		result = append(result, "*."+suffix)
	}
	return result
}

// ServeHTTP routes requests based on method.
// CONNECT requests are handled via handleConnect (tunnel or intercept).
// All other requests are delegated to the inner handler directly.
func (ti *TLSInspector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		ti.handleConnect(w, r)
		return
	}
	ti.config.Handler.ServeHTTP(w, r)
}

// handleConnect processes CONNECT requests.
// First checks outbound rules (even without TLS inspection, the domain is
// known from the CONNECT target). Then determines whether to tunnel or intercept.
func (ti *TLSInspector) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	domain := hostOnly(host)
	port := portFromHost(host, 443)

	// Check outbound rules before tunneling. The connect filter is set by
	// start.go and evaluates the same outbound rules used by the MCP chain.
	ti.mu.RLock()
	filter := ti.connectFilter
	ti.mu.RUnlock()
	if filter != nil {
		if err := filter(domain, port); err != nil {
			ti.logger.Info("CONNECT blocked by outbound rule", "domain", domain, "port", port, "error", err)
			http.Error(w, fmt.Sprintf(`{"error":"outbound_blocked","reason":"%s"}`, err.Error()), http.StatusForbidden)
			return
		}
	}

	if !ti.IsEnabled() || ti.isBypassed(domain) {
		ti.tunnel(w, r)
		return
	}

	ti.intercept(w, r, domain)
}

// isBypassed checks if a domain is in the bypass list.
// Supports exact match and glob patterns (e.g., "*.google.com" matches
// "api.google.com" and "deep.sub.google.com").
func (ti *TLSInspector) isBypassed(domain string) bool {
	ti.mu.RLock()
	defer ti.mu.RUnlock()

	// Exact match
	if ti.bypassSet[domain] {
		return true
	}

	// Glob patterns: "*.suffix" matches domain == suffix or *.suffix
	for _, pattern := range ti.bypassGlobs {
		// pattern is the suffix without the "*." prefix
		if domain == pattern || strings.HasSuffix(domain, "."+pattern) {
			return true
		}
	}

	return false
}

// tunnel creates a raw TCP relay between the client and the target.
// No TLS inspection, no security chain -- just a transparent tunnel.
func (ti *TLSInspector) tunnel(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		ti.logger.Error("ResponseWriter does not support Hijack")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	// Dial the target
	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		ti.logger.Error("failed to dial target for tunnel", "host", r.Host, "error", err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	// Hijack the client connection
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		ti.logger.Error("failed to hijack connection", "error", err)
		targetConn.Close()
		return
	}

	// Send 200 Connection Established to the client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		ti.logger.Error("failed to write CONNECT response", "error", err)
		clientConn.Close()
		targetConn.Close()
		return
	}

	ti.logger.Debug("tunnel established", "host", r.Host)

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, clientConn)
		// Signal the other direction to stop reading
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
		// Signal the other direction to stop reading
		if tc, ok := clientConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
	clientConn.Close()
	targetConn.Close()
}

// intercept performs TLS MITM interception on a CONNECT request.
// It hijacks the client connection, performs a TLS handshake using a
// leaf certificate from the CertCache, reads the inner HTTP request,
// and serves it through the security chain.
func (ti *TLSInspector) intercept(w http.ResponseWriter, r *http.Request, domain string) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		ti.logger.Error("ResponseWriter does not support Hijack")
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	// Hijack the client connection
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		ti.logger.Error("failed to hijack for intercept", "error", err)
		return
	}

	// Send 200 Connection Established to the client
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		ti.logger.Error("failed to write CONNECT response for intercept", "error", err)
		clientConn.Close()
		return
	}

	// Get leaf cert from CertCache
	leafCert, err := ti.config.CertCache.GetCert(domain)
	if err != nil {
		ti.logger.Error("failed to get leaf cert", "domain", domain, "error", err)
		clientConn.Close()
		return
	}

	// Create TLS server on the hijacked connection
	tlsConn := tls.Server(clientConn, &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
	})

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		ti.logger.Error("TLS handshake failed", "domain", domain, "error", err)
		tlsConn.Close()
		return
	}

	ti.logger.Debug("TLS intercept established", "domain", domain)

	// Read and serve inner HTTP requests (loop for keep-alive)
	bufReader := bufio.NewReader(tlsConn)
	for {
		innerReq, err := http.ReadRequest(bufReader)
		if err != nil {
			if err != io.EOF {
				ti.logger.Debug("error reading inner request", "domain", domain, "error", err)
			}
			break
		}

		// Reconstruct full URL so HTTPNormalizer populates Destination correctly
		innerReq.URL.Scheme = "https"
		innerReq.URL.Host = r.Host // original CONNECT target with port
		if innerReq.URL.Path == "" {
			innerReq.URL.Path = "/"
		}
		innerReq.RequestURI = "" // required for http.Client to accept the request

		// Create a response writer that writes back over the TLS connection
		tw := newTLSResponseWriter(tlsConn)
		ti.config.Handler.ServeHTTP(tw, innerReq)

		// Flush any remaining data
		if err := tw.flush(); err != nil {
			ti.logger.Debug("error flushing TLS response", "error", err)
			break
		}

		// Close the body to prevent leaks
		_ = innerReq.Body.Close()

		// Check for Connection: close
		if innerReq.Close {
			break
		}
	}

	tlsConn.Close()
}

// parseBypassList parses the bypass list into exact matches and glob patterns.
// Must be called with the lock held or during initialization.
func (ti *TLSInspector) parseBypassList(domains []string) {
	ti.mu.Lock()
	defer ti.mu.Unlock()
	ti.parseBypassListLocked(domains)
}

// parseBypassListLocked does the actual parsing. Caller must hold the write lock.
func (ti *TLSInspector) parseBypassListLocked(domains []string) {
	ti.bypassSet = make(map[string]bool, len(domains))
	ti.bypassGlobs = nil

	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if strings.HasPrefix(d, "*.") {
			// Glob pattern: store the suffix (e.g., "google.com" for "*.google.com")
			suffix := d[2:]
			ti.bypassGlobs = append(ti.bypassGlobs, suffix)
		} else {
			ti.bypassSet[d] = true
		}
	}
}

// hostOnly extracts the hostname from a host:port string.
// If there's no port, returns the host as-is.
func hostOnly(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

// portFromHost extracts the port from a host:port string.
// Returns defaultPort if no port is present or parsing fails.
func portFromHost(hostPort string, defaultPort int) int {
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return defaultPort
	}
	port := 0
	for _, c := range portStr {
		if c >= '0' && c <= '9' {
			port = port*10 + int(c-'0')
		} else {
			return defaultPort
		}
	}
	if port == 0 {
		return defaultPort
	}
	return port
}

// tlsResponseWriter implements http.ResponseWriter over a TLS connection.
// It writes HTTP/1.1 responses back to the client through the TLS tunnel.
type tlsResponseWriter struct {
	header      http.Header
	wroteHeader bool
	statusCode  int
	conn        net.Conn
}

// newTLSResponseWriter creates a response writer that writes to the given connection.
func newTLSResponseWriter(conn net.Conn) *tlsResponseWriter {
	return &tlsResponseWriter{
		header: make(http.Header),
		conn:   conn,
	}
}

// Header returns the response headers.
func (tw *tlsResponseWriter) Header() http.Header {
	return tw.header
}

// WriteHeader writes the HTTP status line and headers.
func (tw *tlsResponseWriter) WriteHeader(statusCode int) {
	if tw.wroteHeader {
		return
	}
	tw.wroteHeader = true
	tw.statusCode = statusCode

	// Write status line
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Unknown"
	}
	fmt.Fprintf(tw.conn, "HTTP/1.1 %d %s\r\n", statusCode, statusText)

	// Write headers
	for key, values := range tw.header {
		for _, v := range values {
			fmt.Fprintf(tw.conn, "%s: %s\r\n", key, v)
		}
	}

	// End of headers
	fmt.Fprint(tw.conn, "\r\n")
}

// Write writes body bytes to the connection.
// If WriteHeader hasn't been called, it calls WriteHeader(200) first.
func (tw *tlsResponseWriter) Write(b []byte) (int, error) {
	if !tw.wroteHeader {
		tw.WriteHeader(http.StatusOK)
	}
	return tw.conn.Write(b)
}

// flush ensures the response has been written. Called after ServeHTTP returns.
func (tw *tlsResponseWriter) flush() error {
	if !tw.wroteHeader {
		tw.WriteHeader(http.StatusOK)
	}
	return nil
}
