package httpgw

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestTLSInspector_ConnectDisabled verifies that when TLS inspection is disabled,
// CONNECT requests are tunneled without TLS handshake.
func TestTLSInspector_ConnectDisabled(t *testing.T) {
	// Start an echo server as the upstream target
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn) // echo
	}()

	handlerCalled := false
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	inspector := NewTLSInspector(TLSInspectorConfig{
		Enabled: false, // TLS inspection disabled
		Handler: innerHandler,
		Logger:  testLogger(),
	})

	// Create an in-process server
	ts := httptest.NewServer(inspector)
	defer ts.Close()

	// Send CONNECT request
	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	target := echoLn.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	// Read the 200 response
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("failed to read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// Verify tunnel works (send data, get echo back)
	testData := "hello tunnel"
	_, err = fmt.Fprint(conn, testData)
	if err != nil {
		t.Fatalf("failed to write to tunnel: %v", err)
	}

	// Close write side to trigger the echo
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	echoed, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("failed to read echo: %v", err)
	}
	if string(echoed) != testData {
		t.Errorf("expected echo %q, got %q", testData, string(echoed))
	}

	// Handler should NOT have been called (tunnel mode, not intercept)
	if handlerCalled {
		t.Error("handler should not be called in tunnel mode")
	}
}

// TestTLSInspector_ConnectBypassed verifies that when TLS inspection is enabled
// but the domain is in the bypass list, CONNECT requests are tunneled.
func TestTLSInspector_ConnectBypassed(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	certCache, _ := testCertCache(t, time.Hour)

	handlerCalled := false
	inspector := NewTLSInspector(TLSInspectorConfig{
		Enabled:    true,
		BypassList: []string{"example.com"},
		CertCache:  certCache,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		}),
		Logger: testLogger(),
	})

	ts := httptest.NewServer(inspector)
	defer ts.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The proxy tunnels to r.Host (CONNECT target). Use the actual echo address
	// as the CONNECT target and put its IP in the bypass list so the inspector
	// treats it as bypassed.
	echoAddr := echoLn.Addr().String()
	echoHost, _, _ := net.SplitHostPort(echoAddr)
	inspector.SetBypassList([]string{echoHost})

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", echoAddr, echoAddr)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("failed to read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	testData := "bypassed tunnel"
	_, err = fmt.Fprint(conn, testData)
	if err != nil {
		t.Fatalf("failed to write: %v", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}

	echoed, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("failed to read: %v", err)
	}
	if string(echoed) != testData {
		t.Errorf("expected %q, got %q", testData, string(echoed))
	}

	if handlerCalled {
		t.Error("handler should not be called for bypassed domain")
	}
}

// TestTLSInspector_ConnectBypassGlob verifies that glob patterns in the bypass
// list work correctly (e.g., "*.google.com" matches "api.google.com").
func TestTLSInspector_ConnectBypassGlob(t *testing.T) {
	certCache, _ := testCertCache(t, time.Hour)

	inspector := NewTLSInspector(TLSInspectorConfig{
		Enabled:    true,
		BypassList: []string{"*.google.com"},
		CertCache:  certCache,
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Logger:     testLogger(),
	})

	// Test isBypassed directly since full CONNECT test for glob is complex
	if !inspector.isBypassed("api.google.com") {
		t.Error("expected api.google.com to be bypassed by *.google.com")
	}
	if !inspector.isBypassed("deep.sub.google.com") {
		t.Error("expected deep.sub.google.com to be bypassed by *.google.com")
	}
	if !inspector.isBypassed("google.com") {
		t.Error("expected google.com to be bypassed by *.google.com")
	}
	if inspector.isBypassed("notgoogle.com") {
		t.Error("notgoogle.com should not be bypassed")
	}
}

// TestTLSInspector_ConnectIntercept verifies that when TLS inspection is enabled
// and the domain is not bypassed, the proxy performs TLS MITM and passes the
// decrypted request through the handler.
func TestTLSInspector_ConnectIntercept(t *testing.T) {
	certCache, ca := testCertCache(t, time.Hour)

	var receivedHost string
	var receivedPath string
	var receivedScheme string

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.URL.Host
		receivedPath = r.URL.Path
		receivedScheme = r.URL.Scheme
		w.Header().Set("X-Inspected", "true")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "inspected response")
	})

	inspector := NewTLSInspector(TLSInspectorConfig{
		Enabled:   true,
		CertCache: certCache,
		Handler:   innerHandler,
		Logger:    testLogger(),
	})

	ts := httptest.NewServer(inspector)
	defer ts.Close()

	// Connect to the proxy
	conn, err := net.Dial("tcp", strings.TrimPrefix(ts.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send CONNECT to a domain (not in bypass list)
	connectTarget := "secure.example.com:443"
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", connectTarget, connectTarget)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("failed to read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 Connection Established, got %d", resp.StatusCode)
	}

	// Build a TLS client that trusts the test CA
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca.CACertPEM())

	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    caCertPool,
		ServerName: "secure.example.com",
	})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake failed: %v", err)
	}

	// Send an HTTP request over the TLS tunnel
	fmt.Fprint(tlsConn, "GET /api/data HTTP/1.1\r\nHost: secure.example.com\r\nConnection: close\r\n\r\n")

	tlsBr := bufio.NewReader(tlsConn)
	innerResp, err := http.ReadResponse(tlsBr, nil)
	if err != nil {
		t.Fatalf("failed to read inner response: %v", err)
	}
	defer innerResp.Body.Close()

	if innerResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", innerResp.StatusCode)
	}

	body, _ := io.ReadAll(innerResp.Body)
	if string(body) != "inspected response" {
		t.Errorf("expected 'inspected response', got %q", string(body))
	}

	if innerResp.Header.Get("X-Inspected") != "true" {
		t.Error("expected X-Inspected header from handler")
	}

	// Verify the handler received the correct URL info
	if receivedHost != connectTarget {
		t.Errorf("expected host %q, got %q", connectTarget, receivedHost)
	}
	if receivedPath != "/api/data" {
		t.Errorf("expected path '/api/data', got %q", receivedPath)
	}
	if receivedScheme != "https" {
		t.Errorf("expected scheme 'https', got %q", receivedScheme)
	}
}

// TestTLSInspector_NonConnectPassthrough verifies that non-CONNECT requests
// (e.g., GET) are delegated to the handler directly.
func TestTLSInspector_NonConnectPassthrough(t *testing.T) {
	var receivedMethod string

	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "proxied")
	})

	inspector := NewTLSInspector(TLSInspectorConfig{
		Enabled: true,
		Handler: innerHandler,
		Logger:  testLogger(),
	})

	req := httptest.NewRequest("GET", "http://example.com/api", nil)
	rec := httptest.NewRecorder()
	inspector.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != "proxied" {
		t.Errorf("expected 'proxied', got %q", rec.Body.String())
	}
	if receivedMethod != "GET" {
		t.Errorf("expected GET, got %s", receivedMethod)
	}
}

// TestTLSInspector_SetBypassList verifies that the bypass list can be updated
// at runtime and the new list takes effect.
func TestTLSInspector_SetBypassList(t *testing.T) {
	inspector := NewTLSInspector(TLSInspectorConfig{
		Enabled:    true,
		BypassList: []string{"old.example.com"},
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Logger:     testLogger(),
	})

	// Verify initial state
	if !inspector.isBypassed("old.example.com") {
		t.Error("expected old.example.com to be bypassed")
	}
	if inspector.isBypassed("new.example.com") {
		t.Error("new.example.com should not be bypassed yet")
	}

	// Update bypass list
	inspector.SetBypassList([]string{"new.example.com", "*.test.com"})

	// Old domain no longer bypassed
	if inspector.isBypassed("old.example.com") {
		t.Error("old.example.com should no longer be bypassed")
	}
	// New domain bypassed
	if !inspector.isBypassed("new.example.com") {
		t.Error("new.example.com should be bypassed")
	}
	// Glob should work
	if !inspector.isBypassed("api.test.com") {
		t.Error("api.test.com should be bypassed by *.test.com")
	}
}

// TestIsBypassed_ExactMatch tests exact domain matching in the bypass list.
func TestIsBypassed_ExactMatch(t *testing.T) {
	inspector := NewTLSInspector(TLSInspectorConfig{
		Enabled:    true,
		BypassList: []string{"example.com", "api.github.com"},
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Logger:     testLogger(),
	})

	if !inspector.isBypassed("example.com") {
		t.Error("example.com should be bypassed (exact match)")
	}
	if !inspector.isBypassed("api.github.com") {
		t.Error("api.github.com should be bypassed (exact match)")
	}
}

// TestIsBypassed_GlobMatch tests glob pattern matching in the bypass list.
func TestIsBypassed_GlobMatch(t *testing.T) {
	inspector := NewTLSInspector(TLSInspectorConfig{
		Enabled:    true,
		BypassList: []string{"*.example.com"},
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Logger:     testLogger(),
	})

	// Direct subdomain
	if !inspector.isBypassed("sub.example.com") {
		t.Error("sub.example.com should match *.example.com")
	}

	// Deeply nested subdomain
	if !inspector.isBypassed("deep.sub.example.com") {
		t.Error("deep.sub.example.com should match *.example.com")
	}

	// Root domain matches too (*.example.com covers example.com)
	if !inspector.isBypassed("example.com") {
		t.Error("example.com should match *.example.com (root domain)")
	}
}

// TestIsBypassed_NoMatch tests that non-matching domains are not bypassed.
func TestIsBypassed_NoMatch(t *testing.T) {
	inspector := NewTLSInspector(TLSInspectorConfig{
		Enabled:    true,
		BypassList: []string{"example.com", "*.google.com"},
		Handler:    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
		Logger:     testLogger(),
	})

	if inspector.isBypassed("other.com") {
		t.Error("other.com should not be bypassed")
	}
	if inspector.isBypassed("notexample.com") {
		t.Error("notexample.com should not be bypassed")
	}
	if inspector.isBypassed("notgoogle.com") {
		t.Error("notgoogle.com should not be bypassed")
	}
}
