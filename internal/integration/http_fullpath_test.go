package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/httpgw"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
)

// TestHTTPGatewayFullPath_ForwardProxy validates the full HTTP gateway chain for an allowed request:
// Handler normalizes -> identity from context -> PolicyActionInterceptor ->
// OutboundInterceptor -> ResponseScanInterceptor -> passthrough -> forward to upstream.
func TestHTTPGatewayFullPath_ForwardProxy(t *testing.T) {
	logger := testLogger()

	// 1. Create an upstream test server returning 200 OK with JSON body
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"data": "hello"})
	}))
	defer upstream.Close()

	// 2. Mock policy engine returning allow (PolicyActionInterceptor passes through
	//    http_request actions, so engine is only consulted for tool_call types;
	//    engine is still wired to prove the chain is assembled correctly)
	engine := &mockPolicyEngine{
		decision: policy.Decision{
			Allowed:  true,
			RuleID:   "rule-allow-http",
			RuleName: "Allow HTTP",
			Reason:   "allowed by test policy",
		},
	}

	// 3. Passthrough terminal that returns action as-is
	terminal := action.ActionInterceptorFunc(func(ctx context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
		return a, nil
	})

	// 4. Wire: ResponseScanInterceptor -> terminal
	scanner := action.NewResponseScanner()
	responseScanInterceptor := action.NewResponseScanInterceptor(scanner, terminal, action.ScanModeMonitor, true, logger)

	// 5. Wire: OutboundInterceptor (empty rules) -> ResponseScanInterceptor
	dnsResolver := action.NewDNSResolver(logger)
	outboundInterceptor := action.NewOutboundInterceptor(nil, dnsResolver, responseScanInterceptor, logger)

	// 6. Wire: PolicyActionInterceptor -> OutboundInterceptor
	policyInterceptor := action.NewPolicyActionInterceptor(engine, outboundInterceptor, logger)

	// 7. Create httpgw.Handler with the chain
	handler := httpgw.NewHandler(policyInterceptor, logger)
	handler.DisableSSRFProtection() // Test upstream is on localhost

	// 8. Create HTTP request targeting the upstream test server URL
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/api/data", nil)

	// 9. Set identity in request context (simulating auth middleware)
	identity := &action.ActionIdentity{
		ID:        "id-http-001",
		Name:      "http-test-user",
		Roles:     []string{"user"},
		SessionID: "sess-http-001",
	}
	ctx := context.WithValue(req.Context(), httpgw.ContextKeyIdentity, identity)
	req = req.WithContext(ctx)

	// 10. Execute
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Assert: response status 200
	if recorder.Code != http.StatusOK {
		t.Fatalf("response status = %d, want %d; body: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}

	// Assert: response body contains "hello"
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["data"] != "hello" {
		t.Errorf("response body data = %q, want %q", body["data"], "hello")
	}
}

// TestHTTPGatewayFullPath_PolicyDeny validates the full HTTP gateway chain for a denied request.
// The handler maps chain errors wrapping ErrPolicyDenied to HTTP 403 responses with structured JSON.
//
// Note: PolicyActionInterceptor only evaluates tool_call actions (not http_request).
// In production, HTTP gateway denials come from outbound rules or a broader policy
// mechanism. This test uses a deny interceptor head to validate the handler's
// error-to-HTTP-response mapping end-to-end.
func TestHTTPGatewayFullPath_PolicyDeny(t *testing.T) {
	logger := testLogger()

	// 1. Build a deny interceptor that wraps ErrPolicyDenied -- simulates a chain
	//    that denies the HTTP request (same error shape that PolicyActionInterceptor
	//    produces for tool_call denials).
	denyChain := action.ActionInterceptorFunc(func(ctx context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
		return nil, fmt.Errorf("%w: external API calls are blocked", proxy.ErrPolicyDenied)
	})

	// 2. Create httpgw.Handler with the deny chain
	handler := httpgw.NewHandler(denyChain, logger)

	// 3. Create HTTP request targeting any URL
	req := httptest.NewRequest(http.MethodGet, "http://evil.example.com/steal-data", nil)

	// 4. Set identity in request context
	identity := &action.ActionIdentity{
		ID:        "id-http-002",
		Name:      "http-test-user-2",
		Roles:     []string{"user"},
		SessionID: "sess-http-002",
	}
	ctx := context.WithValue(req.Context(), httpgw.ContextKeyIdentity, identity)
	req = req.WithContext(ctx)

	// 5. Execute
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	// Assert: response status 403
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("response status = %d, want %d; body: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}

	// Assert: response body contains JSON with "error" field describing policy denial
	var body map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode response body: %v", err)
	}
	if body["error"] == nil {
		t.Fatal("response body should contain 'error' field")
	}
	errorStr, ok := body["error"].(string)
	if !ok {
		t.Fatalf("'error' field should be a string, got %T", body["error"])
	}
	if errorStr != "policy_denied" {
		t.Errorf("error = %q, want %q", errorStr, "policy_denied")
	}
}
