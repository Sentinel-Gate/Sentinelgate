package sentinelgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestEvaluateAllow(t *testing.T) {
	var receivedBody EvaluateRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/api/v1/policy/evaluate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected content-type: %s", r.Header.Get("Content-Type"))
		}

		if err := json.NewDecoder(r.Body).Decode(&receivedBody); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EvaluateResponse{
			Decision:  DecisionAllow,
			RuleID:    "rule-1",
			RuleName:  "allow-reads",
			Reason:    "action permitted",
			RequestID: "req-123",
			LatencyMs: 2,
		})
	}))
	defer server.Close()

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("test-key"),
	)

	resp, err := client.Evaluate(context.Background(), EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "read_file",
		Protocol:      "mcp",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"developer"},
		Arguments:     map[string]any{"path": "/tmp/test.txt"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
	if resp.RuleID != "rule-1" {
		t.Errorf("expected rule-1, got %s", resp.RuleID)
	}
	if resp.RequestID != "req-123" {
		t.Errorf("expected req-123, got %s", resp.RequestID)
	}

	// Verify request body was sent correctly.
	if receivedBody.ActionType != "tool_call" {
		t.Errorf("expected action_type=tool_call, got %s", receivedBody.ActionType)
	}
	if receivedBody.ActionName != "read_file" {
		t.Errorf("expected action_name=read_file, got %s", receivedBody.ActionName)
	}
	if receivedBody.Protocol != "mcp" {
		t.Errorf("expected protocol=mcp, got %s", receivedBody.Protocol)
	}
	if receivedBody.IdentityName != "agent-1" {
		t.Errorf("expected identity_name=agent-1, got %s", receivedBody.IdentityName)
	}
}

func TestEvaluateDeny(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EvaluateResponse{
			Decision:  DecisionDeny,
			RuleID:    "rule-block-writes",
			RuleName:  "block-writes",
			Reason:    "write operations not permitted",
			HelpURL:   "/admin/policies#rule-block-writes",
			HelpText:  "Contact admin to enable write access",
			RequestID: "req-456",
			LatencyMs: 1,
		})
	}))
	defer server.Close()

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("test-key"),
	)

	_, err := client.Evaluate(context.Background(), EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "write_file",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"reader"},
	})

	if err == nil {
		t.Fatal("expected error on deny, got nil")
	}

	// Verify errors.Is works with sentinel error.
	if !errors.Is(err, ErrPolicyDenied) {
		t.Errorf("expected errors.Is(err, ErrPolicyDenied) to be true, got false. err type: %T", err)
	}

	// Verify errors.As works with PolicyDeniedError.
	var denied *PolicyDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("expected errors.As(err, *PolicyDeniedError) to be true")
	}
	if denied.RuleID != "rule-block-writes" {
		t.Errorf("expected rule_id=rule-block-writes, got %s", denied.RuleID)
	}
	if denied.RuleName != "block-writes" {
		t.Errorf("expected rule_name=block-writes, got %s", denied.RuleName)
	}
	if denied.Reason != "write operations not permitted" {
		t.Errorf("expected reason='write operations not permitted', got %s", denied.Reason)
	}
	if denied.HelpURL != "/admin/policies#rule-block-writes" {
		t.Errorf("expected help_url, got %s", denied.HelpURL)
	}
	if denied.HelpText != "Contact admin to enable write access" {
		t.Errorf("expected help_text, got %s", denied.HelpText)
	}
	if denied.RequestID != "req-456" {
		t.Errorf("expected request_id=req-456, got %s", denied.RequestID)
	}
}

func TestCheck(t *testing.T) {
	t.Run("allow", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(EvaluateResponse{
				Decision:  DecisionAllow,
				RequestID: "req-1",
			})
		}))
		defer server.Close()

		client := NewClient(WithServerAddr(server.URL), WithAPIKey("key"))
		ok, err := client.Check(context.Background(), EvaluateRequest{
			ActionType:    "tool_call",
			ActionName:    "read_file",
			IdentityName:  "agent-1",
			IdentityRoles: []string{"dev"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Error("expected true for allow")
		}
	})

	t.Run("deny", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(EvaluateResponse{
				Decision:  DecisionDeny,
				Reason:    "denied",
				RequestID: "req-2",
			})
		}))
		defer server.Close()

		client := NewClient(WithServerAddr(server.URL), WithAPIKey("key"))
		ok, err := client.Check(context.Background(), EvaluateRequest{
			ActionType:    "tool_call",
			ActionName:    "write_file",
			IdentityName:  "agent-1",
			IdentityRoles: []string{"dev"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Error("expected false for deny")
		}
	})
}

func TestEnvVarConfiguration(t *testing.T) {
	// Save and restore env vars.
	envVars := []string{
		"SENTINELGATE_SERVER_ADDR",
		"SENTINELGATE_API_KEY",
		"SENTINELGATE_PROTOCOL",
		"SENTINELGATE_FAIL_MODE",
		"SENTINELGATE_TIMEOUT",
		"SENTINELGATE_CACHE_TTL",
		"SENTINELGATE_CACHE_MAX_SIZE",
		"SENTINELGATE_IDENTITY_NAME",
		"SENTINELGATE_IDENTITY_ROLES",
	}
	saved := make(map[string]string)
	for _, k := range envVars {
		saved[k] = os.Getenv(k)
	}
	defer func() {
		for k, v := range saved {
			if v == "" {
				os.Unsetenv(k)
			} else {
				os.Setenv(k, v)
			}
		}
	}()

	os.Setenv("SENTINELGATE_SERVER_ADDR", "http://test-server:8080")
	os.Setenv("SENTINELGATE_API_KEY", "env-key-123")
	os.Setenv("SENTINELGATE_PROTOCOL", "a2a")
	os.Setenv("SENTINELGATE_FAIL_MODE", "closed")
	os.Setenv("SENTINELGATE_TIMEOUT", "10")
	os.Setenv("SENTINELGATE_CACHE_TTL", "30s")
	os.Setenv("SENTINELGATE_CACHE_MAX_SIZE", "500")
	os.Setenv("SENTINELGATE_IDENTITY_NAME", "default-agent")
	os.Setenv("SENTINELGATE_IDENTITY_ROLES", "admin,developer")

	client := NewClient()

	if client.serverAddr != "http://test-server:8080" {
		t.Errorf("expected server_addr from env, got %s", client.serverAddr)
	}
	if client.apiKey != "env-key-123" {
		t.Errorf("expected api_key from env, got %s", client.apiKey)
	}
	if client.defaultProtocol != "a2a" {
		t.Errorf("expected protocol=a2a from env, got %s", client.defaultProtocol)
	}
	if client.failMode != "closed" {
		t.Errorf("expected fail_mode=closed from env, got %s", client.failMode)
	}
	if client.timeout != 10*time.Second {
		t.Errorf("expected timeout=10s from env, got %v", client.timeout)
	}
	if client.cacheTTL != 30*time.Second {
		t.Errorf("expected cache_ttl=30s from env, got %v", client.cacheTTL)
	}
	if client.cacheMaxSize != 500 {
		t.Errorf("expected cache_max_size=500 from env, got %d", client.cacheMaxSize)
	}
	if client.identityName != "default-agent" {
		t.Errorf("expected identity_name=default-agent from env, got %s", client.identityName)
	}
	if len(client.identityRoles) != 2 || client.identityRoles[0] != "admin" || client.identityRoles[1] != "developer" {
		t.Errorf("expected identity_roles=[admin,developer] from env, got %v", client.identityRoles)
	}
}

func TestCacheHit(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EvaluateResponse{
			Decision:  DecisionAllow,
			RequestID: fmt.Sprintf("req-%d", callCount.Load()),
		})
	}))
	defer server.Close()

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("key"),
		WithCacheTTL(1*time.Minute),
	)

	req := EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "read_file",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"dev"},
	}

	// First call should hit server.
	resp1, err := client.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	if resp1.RequestID != "req-1" {
		t.Errorf("expected req-1, got %s", resp1.RequestID)
	}

	// Second call should use cache.
	resp2, err := client.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if resp2.RequestID != "req-1" {
		t.Errorf("expected cached req-1, got %s", resp2.RequestID)
	}

	if callCount.Load() != 1 {
		t.Errorf("expected server called once, got %d", callCount.Load())
	}
}

func TestFailOpen(t *testing.T) {
	// Use a listener that immediately closes to simulate unreachable server.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	client := NewClient(
		WithServerAddr("http://"+addr),
		WithAPIKey("key"),
		WithFailMode("open"),
		WithTimeout(500*time.Millisecond),
	)

	resp, err := client.Evaluate(context.Background(), EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "read_file",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"dev"},
	})

	if err != nil {
		t.Fatalf("fail-open should not return error, got: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("fail-open should return allow, got %s", resp.Decision)
	}
}

func TestFailClosed(t *testing.T) {
	// Use a listener that immediately closes to simulate unreachable server.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()

	client := NewClient(
		WithServerAddr("http://"+addr),
		WithAPIKey("key"),
		WithFailMode("closed"),
		WithTimeout(500*time.Millisecond),
	)

	_, err = client.Evaluate(context.Background(), EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "read_file",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"dev"},
	})

	if err == nil {
		t.Fatal("fail-closed should return error")
	}

	if !errors.Is(err, ErrServerUnreachable) {
		t.Errorf("expected ErrServerUnreachable, got: %v (%T)", err, err)
	}

	var srvErr *ServerUnreachableError
	if !errors.As(err, &srvErr) {
		t.Fatalf("expected errors.As(*ServerUnreachableError)")
	}
	if srvErr.Cause == nil {
		t.Error("expected Cause to be set")
	}
}

func TestApprovalPolling(t *testing.T) {
	var pollCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.URL.Path == "/admin/api/v1/policy/evaluate" {
			json.NewEncoder(w).Encode(EvaluateResponse{
				Decision:  DecisionApprovalRequired,
				RequestID: "req-approval-1",
			})
			return
		}

		// Status polling endpoint.
		count := pollCount.Add(1)
		if count >= 2 {
			// Approved on second poll.
			json.NewEncoder(w).Encode(StatusResponse{
				RequestID: "req-approval-1",
				Status:    "allow",
				Decision:  DecisionAllow,
				UpdatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			})
		} else {
			// Still pending.
			json.NewEncoder(w).Encode(StatusResponse{
				RequestID: "req-approval-1",
				Status:    "approval_required",
				Decision:  DecisionApprovalRequired,
				UpdatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			})
		}
	}))
	defer server.Close()

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("key"),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Evaluate(ctx, EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "deploy",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"dev"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow after approval, got %s", resp.Decision)
	}
	if resp.RequestID != "req-approval-1" {
		t.Errorf("expected req-approval-1, got %s", resp.RequestID)
	}
}

func TestTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow response.
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EvaluateResponse{
			Decision:  DecisionAllow,
			RequestID: "req-slow",
		})
	}))
	defer server.Close()

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("key"),
		WithTimeout(200*time.Millisecond),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// With fail-open, timeout is treated as connection error -> allow.
	resp, err := client.Evaluate(ctx, EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "read_file",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"dev"},
	})

	if err != nil {
		t.Fatalf("fail-open with timeout should not return error, got: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow (fail-open), got %s", resp.Decision)
	}
}

func TestRequestBody(t *testing.T) {
	var rawBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&rawBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EvaluateResponse{
			Decision:  DecisionAllow,
			RequestID: "req-body-test",
		})
	}))
	defer server.Close()

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("key"),
	)

	_, err := client.Evaluate(context.Background(), EvaluateRequest{
		ActionType:    "http_request",
		ActionName:    "GET",
		Protocol:      "http",
		Framework:     "langchain",
		Gateway:       "forward-proxy",
		IdentityName:  "bot-1",
		IdentityRoles: []string{"admin", "developer"},
		Arguments:     map[string]any{"url": "https://example.com"},
		Destination: &Destination{
			URL:    "https://example.com/api",
			Domain: "example.com",
			IP:     "93.184.216.34",
			Port:   443,
			Scheme: "https",
			Path:   "/api",
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify snake_case JSON keys matching PolicyEvaluateRequest schema.
	expectedKeys := map[string]bool{
		"action_type":    true,
		"action_name":    true,
		"protocol":       true,
		"framework":      true,
		"gateway":        true,
		"identity_name":  true,
		"identity_roles": true,
		"arguments":      true,
		"destination":    true,
	}

	for key := range rawBody {
		if !expectedKeys[key] {
			t.Errorf("unexpected key in request body: %s", key)
		}
	}

	for key := range expectedKeys {
		if _, ok := rawBody[key]; !ok {
			t.Errorf("missing expected key in request body: %s", key)
		}
	}

	// Verify nested destination has snake_case keys.
	dest, ok := rawBody["destination"].(map[string]any)
	if !ok {
		t.Fatal("destination should be an object")
	}
	destExpected := []string{"url", "domain", "ip", "port", "scheme", "path"}
	for _, key := range destExpected {
		if _, ok := dest[key]; !ok {
			t.Errorf("missing destination key: %s", key)
		}
	}

	// Verify specific values.
	if rawBody["action_type"] != "http_request" {
		t.Errorf("action_type mismatch: %v", rawBody["action_type"])
	}
	if rawBody["action_name"] != "GET" {
		t.Errorf("action_name mismatch: %v", rawBody["action_name"])
	}

	roles, ok := rawBody["identity_roles"].([]any)
	if !ok || len(roles) != 2 {
		t.Errorf("identity_roles mismatch: %v", rawBody["identity_roles"])
	}
}

func TestDefaultProtocolFill(t *testing.T) {
	var receivedBody EvaluateRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EvaluateResponse{
			Decision:  DecisionAllow,
			RequestID: "req-default",
		})
	}))
	defer server.Close()

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("key"),
		WithDefaultProtocol("custom-proto"),
		WithIdentityName("default-agent"),
		WithIdentityRoles([]string{"default-role"}),
	)

	_, err := client.Evaluate(context.Background(), EvaluateRequest{
		ActionType: "tool_call",
		ActionName: "read_file",
		// Protocol, IdentityName, IdentityRoles not set - should use defaults.
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedBody.Protocol != "custom-proto" {
		t.Errorf("expected default protocol 'custom-proto', got '%s'", receivedBody.Protocol)
	}
	if receivedBody.IdentityName != "default-agent" {
		t.Errorf("expected default identity 'default-agent', got '%s'", receivedBody.IdentityName)
	}
	if len(receivedBody.IdentityRoles) != 1 || receivedBody.IdentityRoles[0] != "default-role" {
		t.Errorf("expected default roles [default-role], got %v", receivedBody.IdentityRoles)
	}
}

func TestCacheExpiry(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EvaluateResponse{
			Decision:  DecisionAllow,
			RequestID: fmt.Sprintf("req-%d", count),
		})
	}))
	defer server.Close()

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("key"),
		WithCacheTTL(50*time.Millisecond),
	)

	req := EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "read_file",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"dev"},
	}

	// First call.
	_, err := client.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}

	// Wait for cache to expire.
	time.Sleep(100 * time.Millisecond)

	// Second call should hit server again.
	resp2, err := client.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if resp2.RequestID != "req-2" {
		t.Errorf("expected req-2 after cache expiry, got %s", resp2.RequestID)
	}

	if callCount.Load() != 2 {
		t.Errorf("expected server called twice, got %d", callCount.Load())
	}
}

func TestDenyNotCached(t *testing.T) {
	var callCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EvaluateResponse{
			Decision:  DecisionDeny,
			Reason:    "blocked",
			RequestID: "req-deny",
		})
	}))
	defer server.Close()

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("key"),
		WithCacheTTL(1*time.Minute),
	)

	req := EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "write_file",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"dev"},
	}

	// Both calls should hit the server (deny is not cached).
	client.Evaluate(context.Background(), req)
	client.Evaluate(context.Background(), req)

	if callCount.Load() != 2 {
		t.Errorf("expected deny not cached (2 calls), got %d", callCount.Load())
	}
}

func TestErrorTypes(t *testing.T) {
	t.Run("PolicyDeniedError", func(t *testing.T) {
		err := &PolicyDeniedError{
			RuleName:  "test-rule",
			Reason:    "test reason",
			RequestID: "req-1",
		}
		if err.Error() != "policy denied by rule 'test-rule': test reason" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
		if !errors.Is(err, ErrPolicyDenied) {
			t.Error("PolicyDeniedError should match ErrPolicyDenied")
		}
	})

	t.Run("PolicyDeniedError without rule name", func(t *testing.T) {
		err := &PolicyDeniedError{Reason: "general denial"}
		if err.Error() != "policy denied: general denial" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})

	t.Run("ApprovalTimeoutError", func(t *testing.T) {
		err := &ApprovalTimeoutError{RequestID: "req-2"}
		if err.Error() != "approval timeout for request req-2" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
		if !errors.Is(err, ErrApprovalTimeout) {
			t.Error("ApprovalTimeoutError should match ErrApprovalTimeout")
		}
	})

	t.Run("ServerUnreachableError", func(t *testing.T) {
		cause := fmt.Errorf("connection refused")
		err := &ServerUnreachableError{Cause: cause}
		if err.Error() != "server unreachable: connection refused" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
		if !errors.Is(err, ErrServerUnreachable) {
			t.Error("ServerUnreachableError should match ErrServerUnreachable")
		}
		if errors.Unwrap(err) != cause {
			t.Error("Unwrap should return cause")
		}
	})

	t.Run("SentinelGateError", func(t *testing.T) {
		inner := fmt.Errorf("bad request")
		err := &SentinelGateError{Code: "HTTP_400", Err: inner}
		if err.Error() != "sentinelgate [HTTP_400]: bad request" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
		if errors.Unwrap(err) != inner {
			t.Error("Unwrap should return inner error")
		}
	})
}

func TestWithHTTPClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(EvaluateResponse{
			Decision:  DecisionAllow,
			RequestID: "req-custom-client",
		})
	}))
	defer server.Close()

	customClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	client := NewClient(
		WithServerAddr(server.URL),
		WithAPIKey("key"),
		WithHTTPClient(customClient),
	)

	if client.httpClient != customClient {
		t.Error("expected custom http client to be used")
	}

	resp, err := client.Evaluate(context.Background(), EvaluateRequest{
		ActionType:    "tool_call",
		ActionName:    "test",
		IdentityName:  "agent-1",
		IdentityRoles: []string{"dev"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow, got %s", resp.Decision)
	}
}
