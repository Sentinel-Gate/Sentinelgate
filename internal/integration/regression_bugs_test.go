package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
	"go.uber.org/goleak"
)

// =============================================================================
// Helper
// =============================================================================

// runRegression is a helper that wraps a bug regression test with a consistent
// naming scheme: Regression_<bugID>_<description>.
func runRegression(t *testing.T, bugID string, description string, testFunc func(t *testing.T)) {
	t.Helper()
	t.Run(fmt.Sprintf("Regression_%s_%s", bugID, description), testFunc)
}

// =============================================================================
// Test 7.1: B1 — handleToolsCall must apply namespace filter
// =============================================================================

// TestRegression_Bug1_NamespaceFilterOnToolsCall verifies that handleToolsCall
// checks the namespace filter before routing a tools/call request to the upstream.
//
// BUG B1 (fixed): handleToolsCall did NOT check the namespace filter.
// A client knowing a hidden tool name could call it directly via tools/call,
// even though tools/list correctly hid it.
//
// This test creates two tools (tool_a visible to "guest", secret_tool visible
// only to "admin"), then attempts tools/call on secret_tool with role "guest".
// The call must be rejected with "Tool not found".
func TestRegression_Bug1_NamespaceFilterOnToolsCall(t *testing.T) {
	runRegression(t, "B1", "NamespaceFilterOnToolsCall", func(t *testing.T) {
		// Build a mock upstream that would return data if the call got through.
		upstream := &mockUpstreamRouter{
			toolCallResponse: buildRegressionUpstreamResponse(t, "secret data leaked!"),
			toolListResponse: buildRegressionToolListResponse(t, []string{"tool_a", "secret_tool"}),
		}

		// Allow all tools by policy (the bug is about namespace, not policy).
		policyEngine := &mockRegressionPolicyEngine{
			rules: map[string]policy.Decision{},
		}

		chain, _, _ := buildRegressionChain(policyEngine, upstream)

		// Create a session with role "guest".
		sess := &session.Session{
			ID:           "b1-sess",
			IdentityID:   "b1-id",
			IdentityName: "b1-user",
			Roles:        []auth.Role{"guest"},
			CreatedAt:    time.Now().UTC(),
			ExpiresAt:    time.Now().UTC().Add(time.Hour),
			LastAccess:   time.Now().UTC(),
		}

		// Send tools/call for secret_tool with role "guest".
		// The upstream mock (mockUpstreamRouter) doesn't have namespace filtering,
		// but the *real* UpstreamRouter's handleToolsCall was the buggy code.
		// Since we're testing via the integration chain, and the chain terminates
		// at LegacyAdapter(mockUpstreamRouter), the namespace filter is not present
		// in this path. Instead, we test the UpstreamRouter directly.
		//
		// To test the actual B1 fix, we exercise the UpstreamRouter with its
		// namespace filter set, same as the unit test but at integration level.
		msg := buildRegressionMessage(t, "tools/call", 1, map[string]interface{}{
			"name":      "secret_tool",
			"arguments": map[string]interface{}{},
		}, sess)

		// The chain-level test verifies the tool call goes through the policy engine
		// (which allows it). If B1 were unfixed in the chain path, the tool would
		// return data. Since B1 is fixed in UpstreamRouter, and the chain uses a
		// mock upstream that doesn't filter, we verify at integration level by
		// building a full pipeline with auth that ensures sessions have correct roles.
		result, err := chain.Intercept(context.Background(), msg)

		// With the mock upstream (no namespace filter), the call goes through.
		// The real regression guarantee is that the UpstreamRouter code at
		// upstream_router.go:196-205 checks r.namespaceFilter before routing.
		// We verify the fix hasn't regressed by confirming the chain works and
		// checking the code path is reachable.
		if err != nil {
			t.Fatalf("chain intercept failed (unexpected for mock): %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result from chain")
		}

		// Also verify via a direct UpstreamRouter test (mirrors the unit test).
		// This is the actual B1 regression check.
		t.Run("DirectUpstreamRouter", func(t *testing.T) {
			// Build UpstreamRouter with tools in its cache.
			toolCache := &integrationToolCache{
				tools: map[string]*proxy.RoutableTool{
					"tool_a":      {Name: "tool_a", UpstreamID: "up-1", Description: "Tool A"},
					"secret_tool": {Name: "secret_tool", UpstreamID: "up-2", Description: "Secret"},
				},
			}
			connProvider := &integrationConnProvider{
				connections: map[string]*integrationConn{
					"up-1": newIntegrationConn(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`),
					"up-2": newIntegrationConn(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"secret"}]}}`),
				},
			}

			logger := testLogger()
			router := proxy.NewUpstreamRouter(toolCache, connProvider, logger)

			// Set namespace filter: secret_tool visible only to "admin".
			router.SetNamespaceFilter(&integrationNamespaceFilter{
				visible: map[string]map[string]bool{
					"secret_tool": {"admin": true},
				},
			})

			// Build tools/call message for secret_tool with role "guest".
			callMsg := buildRegressionMessage(t, "tools/call", 1, map[string]interface{}{
				"name":      "secret_tool",
				"arguments": map[string]interface{}{},
			}, &session.Session{
				ID:    "b1-direct-sess",
				Roles: []auth.Role{"guest"},
			})

			resp, err := router.Intercept(context.Background(), callMsg)
			if err != nil {
				t.Fatalf("router.Intercept returned error: %v", err)
			}
			if resp == nil {
				t.Fatal("expected error response, got nil")
			}

			// B1 fix: should get "Tool not found" error, not the secret data.
			var errResp struct {
				Error *struct {
					Code    int64  `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(resp.Raw, &errResp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}
			if errResp.Error == nil {
				t.Fatal("B1 REGRESSION: expected error response for hidden tool, got success — namespace filter not applied on tools/call")
			}
			if errResp.Error.Code != proxy.ErrCodeMethodNotFound {
				t.Errorf("expected error code %d, got %d", proxy.ErrCodeMethodNotFound, errResp.Error.Code)
			}
			if !strings.Contains(errResp.Error.Message, "Tool not found") {
				t.Errorf("expected 'Tool not found' in error message, got %q", errResp.Error.Message)
			}
		})
	})
}

// =============================================================================
// Test 7.2: B2 — Empty roles must not bypass namespace filter
// =============================================================================

// TestRegression_Bug2_EmptyRolesDenied verifies that an identity with empty roles
// sees NO tools when a namespace filter is active.
//
// BUG B2 (fixed): when len(callerRoles) == 0, the namespace filter was skipped
// entirely, allowing identities with no roles to see ALL tools.
func TestRegression_Bug2_EmptyRolesDenied(t *testing.T) {
	runRegression(t, "B2", "EmptyRolesDenied", func(t *testing.T) {
		toolCache := &integrationToolCache{
			tools: map[string]*proxy.RoutableTool{
				"tool_a":      {Name: "tool_a", UpstreamID: "up-1", Description: "Tool A"},
				"secret_tool": {Name: "secret_tool", UpstreamID: "up-2", Description: "Secret"},
			},
		}
		connProvider := &integrationConnProvider{
			connections: map[string]*integrationConn{},
		}

		logger := testLogger()
		router := proxy.NewUpstreamRouter(toolCache, connProvider, logger)

		// Set namespace filter: secret_tool visible only to "admin".
		router.SetNamespaceFilter(&integrationNamespaceFilter{
			visible: map[string]map[string]bool{
				"secret_tool": {"admin": true},
			},
		})

		// Build tools/list message with EMPTY roles.
		listMsg := buildRegressionMessage(t, "tools/list", 1, nil, &session.Session{
			ID:    "b2-sess",
			Roles: []auth.Role{}, // empty roles
		})

		resp, err := router.Intercept(context.Background(), listMsg)
		if err != nil {
			t.Fatalf("router.Intercept returned error: %v", err)
		}
		if resp == nil {
			t.Fatal("expected response, got nil")
		}

		// Parse tool list from response.
		var result struct {
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}
		if err := json.Unmarshal(resp.Raw, &result); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		// B2 fix: empty roles = no tools visible (deny-by-default).
		if len(result.Result.Tools) != 0 {
			names := make([]string, len(result.Result.Tools))
			for i, tool := range result.Result.Tools {
				names[i] = tool.Name
			}
			t.Errorf("B2 REGRESSION: empty roles should see 0 tools, got %d: %v",
				len(result.Result.Tools), names)
		}

		// Also verify that tools/call with empty roles is denied (B1+B2 combined).
		t.Run("EmptyRolesCallDenied", func(t *testing.T) {
			callMsg := buildRegressionMessage(t, "tools/call", 2, map[string]interface{}{
				"name":      "secret_tool",
				"arguments": map[string]interface{}{},
			}, &session.Session{
				ID:    "b2-call-sess",
				Roles: []auth.Role{},
			})

			resp, err := router.Intercept(context.Background(), callMsg)
			if err != nil {
				t.Fatalf("router.Intercept returned error: %v", err)
			}

			var errResp struct {
				Error *struct {
					Code int64 `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(resp.Raw, &errResp); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}
			if errResp.Error == nil {
				t.Error("B2 REGRESSION: empty roles should not be able to call hidden tools")
			}
		})
	})
}

// =============================================================================
// Test 7.3: B3 — API key change on same connID must create new session
// =============================================================================

// TestRegression_Bug3_APIKeyChangeDetected verifies that when a different API key
// is presented on the same connection ID, the cached session is invalidated and
// a new session is created for the new key's identity.
//
// BUG B3 (fixed): session cache ignored API key changes. The cached session from
// key-A was returned to key-B without checking if the key changed, allowing
// session fixation attacks on shared connIDs.
func TestRegression_Bug3_APIKeyChangeDetected(t *testing.T) {
	runRegression(t, "B3", "APIKeyChangeDetected", func(t *testing.T) {
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

		identityA := &auth.Identity{
			ID:    "user-A",
			Name:  "User A",
			Roles: []auth.Role{auth.RoleUser},
		}
		identityB := &auth.Identity{
			ID:    "user-B",
			Name:  "User B",
			Roles: []auth.Role{auth.RoleUser},
		}

		const keyA = "regression-api-key-A-1234"
		const keyB = "regression-api-key-B-5678"

		// Build full pipeline with auth (supports two identities + keys).
		logger := testLogger()
		authStore := memory.NewAuthStore()
		sessStore := memory.NewSessionStore()
		sessSvc := session.NewSessionService(sessStore, session.Config{Timeout: 30 * time.Minute})
		passthrough := proxy.NewPassthroughInterceptor()

		authStore.AddIdentity(identityA)
		authStore.AddIdentity(identityB)
		authStore.AddKey(&auth.APIKey{
			Key:        auth.HashKey(keyA), //nolint:staticcheck // SA1019: backward-compatible key lookup
			IdentityID: "user-A",
			Name:       "key-A",
		})
		authStore.AddKey(&auth.APIKey{
			Key:        auth.HashKey(keyB), //nolint:staticcheck // SA1019: backward-compatible key lookup
			IdentityID: "user-B",
			Name:       "key-B",
		})

		apiKeySvc := auth.NewAPIKeyService(authStore)
		authInterceptor := proxy.NewAuthInterceptor(apiKeySvc, sessSvc, passthrough, logger)
		t.Cleanup(func() {
			authInterceptor.Stop()
			sessStore.Stop()
		})

		connID := "shared-conn-b3"
		ctx := context.WithValue(context.Background(), proxy.ConnectionIDKey, connID)

		// Request 1: authenticate with key-A.
		ctx1 := context.WithValue(ctx, proxy.APIKeyContextKey, keyA)
		msg1 := buildRegressionMessage(t, "test", 1, nil, nil)
		result1, err := authInterceptor.Intercept(ctx1, msg1)
		if err != nil {
			t.Fatalf("request 1 (key-A) failed: %v", err)
		}
		if result1.Session == nil {
			t.Fatal("request 1: expected session, got nil")
		}
		if result1.Session.IdentityID != "user-A" {
			t.Fatalf("request 1: expected identity user-A, got %s", result1.Session.IdentityID)
		}
		sessionA := result1.Session.ID

		// Request 2: authenticate with key-B on SAME connID.
		ctx2 := context.WithValue(ctx, proxy.APIKeyContextKey, keyB)
		msg2 := buildRegressionMessage(t, "test", 2, nil, nil)
		result2, err := authInterceptor.Intercept(ctx2, msg2)
		if err != nil {
			t.Fatalf("request 2 (key-B) failed: %v", err)
		}
		if result2.Session == nil {
			t.Fatal("request 2: expected session, got nil")
		}

		// B3 fix: request 2 must use key-B's identity (user-B), NOT key-A's.
		if result2.Session.IdentityID != "user-B" {
			t.Errorf("B3 REGRESSION: request 2 with key-B got identity %q, want %q. "+
				"Cached session from key-A was reused without re-validating!",
				result2.Session.IdentityID, "user-B")
		}

		// Sessions must be different.
		if result2.Session.ID == sessionA {
			t.Errorf("B3 REGRESSION: request 2 with key-B got same session ID as key-A (%s)", sessionA)
		}
	})
}

// =============================================================================
// Test 7.4: B6 — forwardToUpstream must handle >10 notifications
// =============================================================================

// TestRegression_Bug6_NotificationFloodHandled verifies that forwardToUpstream
// handles any number of notifications before the real response without losing it.
//
// BUG B6 (fixed): the loop had maxAttempts=10 which caused it to fail when 10+
// notifications preceded the response. The fix removed the attempt limit and
// uses only the 30s timeout as a guard.
func TestRegression_Bug6_NotificationFloodHandled(t *testing.T) {
	runRegression(t, "B6", "NotificationFloodHandled", func(t *testing.T) {
		toolCache := &integrationToolCache{
			tools: map[string]*proxy.RoutableTool{
				"flood_tool": {Name: "flood_tool", UpstreamID: "up-flood", Description: "Flood tool"},
			},
		}

		// Create a channel-based connection with 20 notifications + 1 response.
		const numNotifications = 20
		ch := make(chan []byte, numNotifications+1)
		for i := 0; i < numNotifications; i++ {
			notification := fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"token":"t","progress":%d}}`, i)
			ch <- []byte(notification)
		}
		// The real response after all notifications.
		ch <- []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"survived flood"}]}}`)

		connProvider := &integrationConnProvider{
			connections: map[string]*integrationConn{
				"up-flood": {
					writer: &integrationWriter{},
					lineCh: ch,
				},
			},
		}

		logger := testLogger()
		router := proxy.NewUpstreamRouter(toolCache, connProvider, logger)

		msg := buildRegressionMessage(t, "tools/call", 1, map[string]interface{}{
			"name":      "flood_tool",
			"arguments": map[string]interface{}{},
		}, nil)

		resp, err := router.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("B6 REGRESSION: expected no error with %d notifications, got: %v", numNotifications, err)
		}
		if resp == nil {
			t.Fatal("B6 REGRESSION: expected response, got nil")
		}

		// Verify we got the real response content.
		var parsed struct {
			Result struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(resp.Raw, &parsed); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if len(parsed.Result.Content) == 0 || parsed.Result.Content[0].Text != "survived flood" {
			t.Errorf("B6 REGRESSION: expected response text 'survived flood', got %+v", parsed.Result)
		}

		// Also test with exactly 50 notifications (well beyond the old limit of 10).
		t.Run("50_notifications", func(t *testing.T) {
			const n = 50
			ch2 := make(chan []byte, n+1)
			for i := 0; i < n; i++ {
				ch2 <- []byte(fmt.Sprintf(`{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":%d}}`, i))
			}
			ch2 <- []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"fifty done"}]}}`)

			connProvider2 := &integrationConnProvider{
				connections: map[string]*integrationConn{
					"up-flood": {writer: &integrationWriter{}, lineCh: ch2},
				},
			}
			router2 := proxy.NewUpstreamRouter(toolCache, connProvider2, logger)

			msg2 := buildRegressionMessage(t, "tools/call", 1, map[string]interface{}{
				"name":      "flood_tool",
				"arguments": map[string]interface{}{},
			}, nil)

			resp2, err := router2.Intercept(context.Background(), msg2)
			if err != nil {
				t.Fatalf("50 notifications: unexpected error: %v", err)
			}

			var parsed2 struct {
				Result struct {
					Content []struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"result"`
			}
			if err := json.Unmarshal(resp2.Raw, &parsed2); err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}
			if len(parsed2.Result.Content) == 0 || parsed2.Result.Content[0].Text != "fifty done" {
				t.Errorf("expected 'fifty done', got %+v", parsed2.Result)
			}
		})
	})
}

// =============================================================================
// Test 7.5: B7 — Disabled policies must not be enforced at startup
// =============================================================================

// TestRegression_Bug7_DisabledPolicyNotEnforcedAtStartup verifies that
// NewPolicyService respects the Enabled flag on policies. Disabled policies
// must NOT have their rules compiled or enforced.
//
// BUG B7 (fixed): NewPolicyService loaded ALL policies without checking Enabled.
// Reload() correctly filtered by Enabled, creating inconsistency between boot
// and reload behavior.
func TestRegression_Bug7_DisabledPolicyNotEnforcedAtStartup(t *testing.T) {
	runRegression(t, "B7", "DisabledPolicyNotEnforcedAtStartup", func(t *testing.T) {
		ctx := context.Background()
		logger := testLogger()

		policyStore := memory.NewPolicyStore()

		// Add an ENABLED policy that allows safe_* tools.
		policyStore.AddPolicy(&policy.Policy{
			ID:      "enabled-pol",
			Name:    "Enabled Policy",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "allow-safe",
					Name:      "Allow safe tools",
					Priority:  50,
					ToolMatch: "safe_*",
					Condition: "true",
					Action:    policy.ActionAllow,
				},
			},
		})

		// Add a DISABLED policy that denies dangerous_tool.
		policyStore.AddPolicy(&policy.Policy{
			ID:      "disabled-pol",
			Name:    "Disabled Policy",
			Enabled: false, // DISABLED
			Rules: []policy.Rule{
				{
					ID:        "deny-dangerous",
					Name:      "Deny dangerous",
					Priority:  100, // higher priority
					ToolMatch: "dangerous_tool",
					Condition: "true",
					Action:    policy.ActionDeny,
				},
			},
		})

		policySvc, err := service.NewPolicyService(ctx, policyStore, logger)
		if err != nil {
			t.Fatalf("NewPolicyService failed: %v", err)
		}

		// Evaluate "dangerous_tool" right after boot.
		// B7 fix: should be ALLOWED (disabled policy not enforced).
		decision, err := policySvc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:      "dangerous_tool",
			ToolArguments: map[string]interface{}{},
			UserRoles:     []string{"user"},
			SessionID:     "b7-sess",
			IdentityID:    "b7-id",
			RequestTime:   time.Now(),
			SkipCache:     true,
		})
		if err != nil {
			t.Fatalf("Evaluate failed: %v", err)
		}

		if !decision.Allowed {
			t.Errorf("B7 REGRESSION: disabled policy enforced at boot! "+
				"'dangerous_tool' was DENIED by rule=%q, but the policy is Enabled=false",
				decision.RuleID)
		}

		// Verify that safe_* tools from the enabled policy still work.
		decision, err = policySvc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:      "safe_read",
			ToolArguments: map[string]interface{}{},
			UserRoles:     []string{"user"},
			SessionID:     "b7-sess",
			IdentityID:    "b7-id",
			RequestTime:   time.Now(),
			SkipCache:     true,
		})
		if err != nil {
			t.Fatalf("Evaluate(safe_read) failed: %v", err)
		}
		if !decision.Allowed {
			t.Errorf("safe_read should be allowed by enabled policy, got denied: rule=%s", decision.RuleID)
		}
	})
}

// =============================================================================
// Test 7.6: B8 — Admin API body size limit
// =============================================================================

// TestRegression_Bug8_AdminBodySizeLimit verifies that the admin API rejects
// oversized request bodies. The key property is that readJSON uses
// http.MaxBytesReader to prevent memory exhaustion.
//
// BUG B8 (fixed): readJSON had no body size limit (no MaxBytesReader), allowing
// memory exhaustion attacks from localhost.
func TestRegression_Bug8_AdminBodySizeLimit(t *testing.T) {
	runRegression(t, "B8", "AdminBodySizeLimit", func(t *testing.T) {
		// Use the full regression admin env to test through the HTTP handler.
		env := setupRegressionAdminEnv(t)

		// Create a 15MB oversized body (exceeds the 10MB MaxBytesReader limit).
		const bodySize = 15 * 1024 * 1024
		body := make([]byte, bodySize)
		copy(body, []byte(`{"name":"`))
		for i := 8; i < bodySize-2; i++ {
			body[i] = 'X'
		}
		copy(body[bodySize-2:], []byte(`"}`))

		// POST to a JSON API endpoint. The readJSON function wraps the body
		// with http.MaxBytesReader(nil, r.Body, 10MB). If the body exceeds
		// this limit, the JSON decoder will get a read error.
		req, err := http.NewRequest(http.MethodPost, env.server.URL+"/admin/api/upstreams", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: regressionCSRFToken})
		req.Header.Set("X-CSRF-Token", regressionCSRFToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		// B8 fix: the request must be REJECTED (not 2xx).
		// The exact error status depends on the handler's error handling path:
		// - readJSONBody returns 413 (Request Entity Too Large) for MaxBytesError
		// - readJSON-based handlers return 400 (Bad Request) for all decode errors
		// Both are acceptable outcomes — the key property is that the oversized
		// body is rejected (not silently accepted/buffered in full).
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			t.Errorf("B8 REGRESSION: oversized body should be rejected, got success status %d", resp.StatusCode)
		}
		if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadRequest {
			respBody, _ := io.ReadAll(resp.Body)
			t.Errorf("B8: unexpected status %d for oversized body, body=%s",
				resp.StatusCode, truncateStr(string(respBody), 200))
		}

		// Verify normal-sized body is accepted (not rejected by size limit).
		t.Run("NormalBodyAccepted", func(t *testing.T) {
			normalBody := map[string]interface{}{
				"name":    "B8 Regression Policy",
				"enabled": true,
				"rules": []map[string]interface{}{
					{
						"name":       "test",
						"priority":   1,
						"tool_match": "*",
						"condition":  "true",
						"action":     "allow",
					},
				},
			}
			resp2 := env.doJSON(t, "POST", "/admin/api/policies", normalBody)
			defer func() { _ = resp2.Body.Close() }()

			if resp2.StatusCode == http.StatusRequestEntityTooLarge {
				t.Error("B8 REGRESSION: normal-sized body should not be rejected with 413")
			}
			// 201 Created is the expected success status for policy creation.
			if resp2.StatusCode != http.StatusCreated {
				body, _ := io.ReadAll(resp2.Body)
				t.Logf("normal body response: status=%d, body=%s", resp2.StatusCode, truncateStr(string(body), 200))
			}
		})
	})
}

// truncateStr returns the first n characters of s, appending "..." if truncated.
func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// =============================================================================
// Test 7.5: Goroutine leak detection
// =============================================================================

// TestRegression_GoroutineLeak verifies that the AuthInterceptor's cleanup
// goroutine does not leak when Stop() is called, and that Start/Stop cycles
// are clean.
func TestRegression_GoroutineLeak(t *testing.T) {
	runRegression(t, "GoroutineLeak", "AuthInterceptorStartStop", func(t *testing.T) {
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

		logger := testLogger()
		authStore := memory.NewAuthStore()
		sessStore := memory.NewSessionStore()
		sessSvc := session.NewSessionService(sessStore, session.Config{Timeout: 30 * time.Minute})
		passthrough := proxy.NewPassthroughInterceptor()

		// Cycle 1: create, start cleanup, stop.
		interceptor1 := proxy.NewAuthInterceptorWithConfig(
			auth.NewAPIKeyService(authStore),
			sessSvc,
			passthrough,
			logger,
			100*time.Millisecond, // fast cleanup for test
			5*time.Minute,
		)
		ctx1, cancel1 := context.WithCancel(context.Background())
		interceptor1.StartCleanup(ctx1)

		// Let the cleanup goroutine run at least once.
		time.Sleep(150 * time.Millisecond)

		cancel1()
		interceptor1.Stop()
		sessStore.Stop()

		// goleak.VerifyNone at the end of this function will catch leaks.
	})

	runRegression(t, "GoroutineLeak", "FullPipelineStartStop", func(t *testing.T) {
		defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

		policyEngine := &mockRegressionPolicyEngine{
			rules: map[string]policy.Decision{},
		}
		upstream := &mockUpstreamRouter{
			toolCallResponse: buildRegressionUpstreamResponse(t, "ok"),
		}

		const validKey = "goroutine-leak-test-key-12345678"
		testIdentity := &auth.Identity{
			ID:    "leak-id",
			Name:  "leak-user",
			Roles: []auth.Role{auth.RoleUser},
		}

		pipe := buildFullPipeline(t, policyEngine, upstream, validKey, testIdentity)

		// Send one request through the pipeline.
		ctx := context.WithValue(context.Background(), proxy.APIKeyContextKey, validKey)
		msg := buildRegressionMessage(t, "tools/call", 1, map[string]interface{}{
			"name":      "test_tool",
			"arguments": map[string]interface{}{},
		}, nil)

		_, err := pipe.chain.Intercept(ctx, msg)
		if err != nil {
			// Might fail (tool not found in mock) — that's fine, we're testing leak.
			if !errors.Is(err, proxy.ErrPolicyDenied) {
				// Non-policy errors are acceptable for this test.
				_ = err
			}
		}

		// t.Cleanup in buildFullPipeline will call authInterceptor.Stop()
		// and sessStore.Stop(). goleak.VerifyNone verifies no goroutines leaked.
	})
}

// =============================================================================
// Mock types for integration-level regression tests
// =============================================================================

// integrationToolCache implements proxy.ToolCacheReader for regression tests.
type integrationToolCache struct {
	tools map[string]*proxy.RoutableTool
}

func (c *integrationToolCache) GetTool(name string) (*proxy.RoutableTool, bool) {
	t, ok := c.tools[name]
	return t, ok
}

func (c *integrationToolCache) GetAllTools() []*proxy.RoutableTool {
	result := make([]*proxy.RoutableTool, 0, len(c.tools))
	for _, t := range c.tools {
		result = append(result, t)
	}
	return result
}

func (c *integrationToolCache) IsAmbiguous(name string) (bool, []string) {
	return false, nil
}

// integrationConnProvider implements proxy.UpstreamConnectionProvider.
type integrationConnProvider struct {
	connections map[string]*integrationConn
}

type integrationConn struct {
	writer *integrationWriter
	lineCh <-chan []byte
}

func newIntegrationConn(responseJSON string) *integrationConn {
	ch := make(chan []byte, 1)
	ch <- []byte(responseJSON)
	return &integrationConn{
		writer: &integrationWriter{},
		lineCh: ch,
	}
}

type integrationWriter struct {
	buf []byte
}

func (w *integrationWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	return len(p), nil
}

func (w *integrationWriter) Close() error {
	return nil
}

func (p *integrationConnProvider) GetConnection(upstreamID string) (io.WriteCloser, <-chan []byte, error) {
	conn, ok := p.connections[upstreamID]
	if !ok {
		return nil, nil, fmt.Errorf("upstream %s not connected", upstreamID)
	}
	return conn.writer, conn.lineCh, nil
}

func (p *integrationConnProvider) AllConnected() bool {
	return true
}

// integrationNamespaceFilter implements proxy.NamespaceFilter for regression tests.
type integrationNamespaceFilter struct {
	visible map[string]map[string]bool // toolName -> role -> visible
}

func (f *integrationNamespaceFilter) IsToolVisible(toolName string, roles []string) bool {
	toolRoles, ok := f.visible[toolName]
	if !ok {
		return true // not configured = visible
	}
	for _, r := range roles {
		if toolRoles[r] {
			return true
		}
	}
	return false
}

// Suppress "imported and not used" for mcp package.
var _ = mcp.ClientToServer
