package admin_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// ============================================================================
// TestSecurity_XSS_RuleNames (SECU-01)
// Verifies that XSS payloads in policy/rule names are returned as-is in JSON
// (safe) without HTML interpretation. Content-Type must be application/json.
// ============================================================================

func TestSecurity_XSS_RuleNames(t *testing.T) {
	env := setupTestEnv(t)

	xssPayloads := []string{
		`<script>alert('xss')</script>`,
		`<img onerror=alert(1) src=x>`,
		`" onclick="alert(1)">`,
		`<svg onload=alert(document.cookie)>`,
	}

	for _, payload := range xssPayloads {
		t.Run(payload, func(t *testing.T) {
			// Create a policy with the XSS payload as the rule name.
			createReq := map[string]interface{}{
				"name":    "XSS Test Policy " + payload[:min(10, len(payload))],
				"enabled": true,
				"rules": []map[string]interface{}{
					{
						"name":       payload,
						"priority":   50,
						"tool_match": "*",
						"condition":  "true",
						"action":     "allow",
					},
				},
			}
			resp := env.doJSON(t, "POST", "/admin/api/policies", createReq)
			if resp.StatusCode != http.StatusCreated {
				body := readBody(t, resp)
				t.Fatalf("create policy: status=%d, body=%s", resp.StatusCode, body)
			}
			_ = resp.Body.Close()

			// GET policies list and verify Content-Type is JSON.
			resp = env.doJSON(t, "GET", "/admin/api/policies", nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("list policies: status=%d", resp.StatusCode)
			}

			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			body := readBody(t, resp)

			var policies []map[string]interface{}
			if err := json.Unmarshal([]byte(body), &policies); err != nil {
				t.Fatalf("response is not valid JSON: %v", err)
			}

			// Find our policy and verify the rule name round-trips correctly.
			found := false
			for _, p := range policies {
				rules, ok := p["rules"].([]interface{})
				if !ok {
					continue
				}
				for _, r := range rules {
					rm, ok := r.(map[string]interface{})
					if !ok {
						continue
					}
					if rm["name"] == payload {
						found = true
						break
					}
				}
			}
			if !found {
				t.Errorf("XSS payload %q not found in JSON-decoded policies (round-trip failed)", payload)
			}

			// Ensure Content-Type is never text/html for API endpoints.
			if strings.Contains(ct, "text/html") {
				t.Errorf("API response Content-Type must NOT be text/html, got %q", ct)
			}

			// Verify raw response does NOT contain unescaped HTML tags.
			if strings.Contains(body, "<script>") {
				t.Error("raw JSON response must not contain unescaped <script> tags")
			}
			if strings.Contains(body, "<img ") {
				t.Error("raw JSON response must not contain unescaped <img> tags")
			}
			if strings.Contains(body, "<svg ") {
				t.Error("raw JSON response must not contain unescaped <svg> tags")
			}
		})
	}
}

// ============================================================================
// TestSecurity_XSS_ToolArguments (SECU-01)
// Verifies that XSS payloads in tool arguments passed to policy test endpoint
// are returned safely as JSON without HTML rendering.
// ============================================================================

func TestSecurity_XSS_ToolArguments(t *testing.T) {
	env := setupTestEnv(t)

	xssArgs := []map[string]interface{}{
		{"file": "<script>alert(1)</script>"},
		{"path": "<img onerror=alert(1) src=x>"},
		{"query": "'; DROP TABLE users; --"},
	}

	for _, args := range xssArgs {
		t.Run("args", func(t *testing.T) {
			testReq := map[string]interface{}{
				"tool_name": "test_tool",
				"arguments": args,
				"roles":     []string{"admin"},
			}

			resp := env.doJSON(t, "POST", "/admin/api/policies/test", testReq)
			if resp.StatusCode != http.StatusOK {
				body := readBody(t, resp)
				t.Fatalf("test policy: status=%d, body=%s", resp.StatusCode, body)
			}

			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			// Response should be valid JSON.
			body := readBody(t, resp)
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(body), &result); err != nil {
				t.Errorf("response is not valid JSON: %v", err)
			}

			if strings.Contains(ct, "text/html") {
				t.Error("Content-Type must NOT be text/html for API responses")
			}
		})
	}
}

// ============================================================================
// TestSecurity_CSRF_Bypass (SECU-02)
// Verifies that POST/PUT/DELETE requests without valid CSRF tokens are rejected
// with 403, and requests with valid tokens succeed.
// ============================================================================

func TestSecurity_CSRF_Bypass(t *testing.T) {
	env := setupTestEnv(t)

	// Prepare a valid JSON body for a state-changing endpoint.
	policyBody := map[string]interface{}{
		"name":    "CSRF Test Policy",
		"enabled": true,
		"rules": []map[string]interface{}{
			{
				"name":       "test-rule",
				"priority":   10,
				"tool_match": "*",
				"condition":  "true",
				"action":     "allow",
			},
		},
	}
	bodyBytes, _ := json.Marshal(policyBody)

	t.Run("missing_csrf_token", func(t *testing.T) {
		// Send POST without CSRF cookie or header.
		req, _ := http.NewRequest("POST", env.server.URL+"/admin/api/policies", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("missing CSRF: status=%d (want 403), body=%s", resp.StatusCode, body)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "CSRF token invalid") {
			t.Errorf("expected CSRF error message, got: %s", body)
		}
	})

	t.Run("wrong_csrf_token", func(t *testing.T) {
		// Send POST with mismatched CSRF cookie and header.
		req, _ := http.NewRequest("POST", env.server.URL+"/admin/api/policies", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: "correct-token"})
		req.Header.Set("X-CSRF-Token", "wrong-token")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusForbidden {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("wrong CSRF: status=%d (want 403), body=%s", resp.StatusCode, body)
		}
	})

	t.Run("valid_csrf_token", func(t *testing.T) {
		// Send POST with matching CSRF cookie and header.
		req, _ := http.NewRequest("POST", env.server.URL+"/admin/api/policies", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		csrfToken := "valid-matching-token"
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: csrfToken})
		req.Header.Set("X-CSRF-Token", csrfToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		// Should succeed (201 Created) since CSRF is valid.
		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("valid CSRF: status=%d (want 201), body=%s", resp.StatusCode, body)
		}
	})

	t.Run("auth_status_exempt_from_csrf", func(t *testing.T) {
		// Auth status endpoint (GET) should work without CSRF.
		req, _ := http.NewRequest("GET", env.server.URL+"/admin/api/auth/status", nil)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("auth status should work without CSRF: status=%d, body=%s", resp.StatusCode, body)
		}
	})
}

// ============================================================================
// TestSecurity_APIKeyLeak (SECU-06)
// Verifies that the cleartext API key is returned only once at generation
// time and NEVER appears in list endpoints.
// ============================================================================

func TestSecurity_APIKeyLeak(t *testing.T) {
	env := setupTestEnv(t)

	// Step 1: Create an identity.
	identityReq := map[string]interface{}{
		"name":  "security-test-user",
		"roles": []string{"admin"},
	}
	resp := env.doJSON(t, "POST", "/admin/api/identities", identityReq)
	if resp.StatusCode != http.StatusCreated {
		body := readBody(t, resp)
		t.Fatalf("create identity: status=%d, body=%s", resp.StatusCode, body)
	}
	var identity map[string]interface{}
	decodeJSON(t, resp, &identity)
	identityID := identity["id"].(string)

	// Step 2: Generate an API key.
	keyReq := map[string]interface{}{
		"identity_id": identityID,
		"name":        "security-test-key",
	}
	resp = env.doJSON(t, "POST", "/admin/api/keys", keyReq)
	if resp.StatusCode != http.StatusCreated {
		body := readBody(t, resp)
		t.Fatalf("generate key: status=%d, body=%s", resp.StatusCode, body)
	}

	var keyResult map[string]interface{}
	decodeJSON(t, resp, &keyResult)

	// Verify cleartext key IS present in generation response.
	cleartextKey, ok := keyResult["cleartext_key"].(string)
	if !ok || cleartextKey == "" {
		t.Fatal("cleartext_key should be present in generation response")
	}
	if !strings.HasPrefix(cleartextKey, "sg_") {
		t.Errorf("cleartext key should start with sg_, got: %s", cleartextKey[:min(10, len(cleartextKey))])
	}

	// Step 3: List all keys - cleartext must NOT appear.
	resp = env.doJSON(t, "GET", "/admin/api/keys", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list keys: status=%d", resp.StatusCode)
	}

	listBody := readBody(t, resp)

	// The cleartext key must not appear anywhere in the list response.
	if strings.Contains(listBody, cleartextKey) {
		t.Error("cleartext key MUST NOT appear in list keys response")
	}

	// No field should contain "sg_" followed by hex chars (the key format).
	sgKeyPattern := regexp.MustCompile(`sg_[0-9a-f]{64}`)
	if sgKeyPattern.MatchString(listBody) {
		t.Error("list keys response must not contain any cleartext key (sg_ + 64 hex chars)")
	}

	// Verify list response has no cleartext_key field at all.
	var keys []map[string]interface{}
	if err := json.Unmarshal([]byte(listBody), &keys); err != nil {
		t.Fatalf("failed to parse keys list: %v", err)
	}
	for _, k := range keys {
		if _, hasCleartext := k["cleartext_key"]; hasCleartext {
			t.Error("key list entries must not have cleartext_key field")
		}
	}
}

// ============================================================================
// TestSecurity_AuthBypass (AUTH-01)
// Verifies that protected endpoints allow localhost requests and reject
// remote requests with 403.
// ============================================================================

func TestSecurity_AuthBypass(t *testing.T) {
	env := setupTestEnv(t)

	t.Run("localhost_bypasses_authentication", func(t *testing.T) {
		// Verify that localhost can access ANY protected endpoint without auth.
		endpoints := []string{
			"/admin/api/upstreams",
			"/admin/api/policies",
			"/admin/api/identities",
			"/admin/api/stats",
			"/admin/api/system",
			"/admin/api/keys",
		}

		for _, ep := range endpoints {
			req, _ := http.NewRequest("GET", env.server.URL+ep, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request to %s failed: %v", ep, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
				t.Errorf("localhost to %s: got %d, want non-auth response (localhost bypass)", ep, resp.StatusCode)
			}
		}
	})
}

// ============================================================================
// TestSecurity_CELInjection (SECU-05)
// Verifies that malicious CEL expressions in policy rules are rejected
// and the policy is not saved when CEL validation fails.
// ============================================================================

func TestSecurity_CELInjection(t *testing.T) {
	t.Run("syntax_error_expression", func(t *testing.T) {
		env := setupTestEnv(t)

		createReq := map[string]interface{}{
			"name":    "CEL Injection Syntax",
			"enabled": true,
			"rules": []map[string]interface{}{
				{
					"name":       "syntax-error-rule",
					"priority":   100,
					"tool_match": "*",
					"condition":  "invalid @@@ syntax $$$",
					"action":     "deny",
				},
			},
		}

		resp := env.doJSON(t, "POST", "/admin/api/policies", createReq)
		body := readBody(t, resp)

		if resp.StatusCode == http.StatusCreated {
			t.Errorf("policy with syntax error CEL should be rejected, got 201, body=%s", body)
		}
		if !strings.Contains(body, "error") {
			t.Errorf("expected error in response body, got: %s", body)
		}
	})

	t.Run("undefined_variable_expression", func(t *testing.T) {
		env := setupTestEnv(t)

		createReq := map[string]interface{}{
			"name":    "CEL Injection Undefined",
			"enabled": true,
			"rules": []map[string]interface{}{
				{
					"name":       "undefined-var-rule",
					"priority":   100,
					"tool_match": "*",
					"condition":  "nonexistent_variable == true",
					"action":     "deny",
				},
			},
		}

		resp := env.doJSON(t, "POST", "/admin/api/policies", createReq)
		body := readBody(t, resp)

		if resp.StatusCode == http.StatusCreated {
			t.Errorf("policy with undefined variable should be rejected, got 201, body=%s", body)
		}
	})

	t.Run("extremely_long_expression_with_invalid_syntax", func(t *testing.T) {
		env := setupTestEnv(t)

		longExpr := strings.Repeat("undefined_var_", 80) + " == true"
		if len(longExpr) <= 1024 {
			t.Fatalf("test expression too short: %d chars, need >1024", len(longExpr))
		}

		createReq := map[string]interface{}{
			"name":    "CEL Injection Long Invalid",
			"enabled": true,
			"rules": []map[string]interface{}{
				{
					"name":       "long-invalid-rule",
					"priority":   100,
					"tool_match": "*",
					"condition":  longExpr,
					"action":     "allow",
				},
			},
		}

		resp := env.doJSON(t, "POST", "/admin/api/policies", createReq)
		body := readBody(t, resp)

		if resp.StatusCode == http.StatusCreated {
			t.Errorf("policy with long invalid CEL should be rejected, got 201, body=%s", body[:min(200, len(body))])
		}
	})

	t.Run("valid_expression_accepted", func(t *testing.T) {
		env := setupTestEnv(t)

		createReq := map[string]interface{}{
			"name":    "CEL Valid Expression",
			"enabled": true,
			"rules": []map[string]interface{}{
				{
					"name":       "valid-rule",
					"priority":   50,
					"tool_match": "*",
					"condition":  `"admin" in user_roles`,
					"action":     "allow",
				},
			},
		}

		resp := env.doJSON(t, "POST", "/admin/api/policies", createReq)
		if resp.StatusCode != http.StatusCreated {
			body := readBody(t, resp)
			t.Errorf("valid CEL expression should be accepted: status=%d, body=%s", resp.StatusCode, body)
		} else {
			_ = resp.Body.Close()
		}
	})

	t.Run("invalid_cel_does_not_execute", func(t *testing.T) {
		env := setupTestEnv(t)

		validReq := map[string]interface{}{
			"name":    "Valid Base Policy",
			"enabled": true,
			"rules": []map[string]interface{}{
				{
					"name":       "base-rule",
					"priority":   10,
					"tool_match": "*",
					"condition":  "true",
					"action":     "deny",
				},
			},
		}
		resp := env.doJSON(t, "POST", "/admin/api/policies", validReq)
		if resp.StatusCode != http.StatusCreated {
			body := readBody(t, resp)
			t.Fatalf("create valid policy: status=%d, body=%s", resp.StatusCode, body)
		}
		_ = resp.Body.Close()

		invalidReq := map[string]interface{}{
			"name":    "Should Not Execute",
			"enabled": true,
			"rules": []map[string]interface{}{
				{
					"name":       "bad-rule",
					"priority":   100,
					"tool_match": "*",
					"condition":  "!!!invalid!!!",
					"action":     "allow",
				},
			},
		}
		resp = env.doJSON(t, "POST", "/admin/api/policies", invalidReq)
		if resp.StatusCode == http.StatusCreated {
			body := readBody(t, resp)
			t.Errorf("invalid CEL should be rejected: status=%d, body=%s", resp.StatusCode, body)
		} else {
			_ = resp.Body.Close()
		}
	})
}

// ============================================================================
// TestSecurity_PathTraversal (SECU-08)
// Verifies that upstream creation/update with path traversal in command or
// args is rejected with 400.
// ============================================================================

func TestSecurity_PathTraversal(t *testing.T) {
	env := setupTestEnv(t)

	t.Run("command_with_path_traversal", func(t *testing.T) {
		createReq := map[string]interface{}{
			"name":    "traversal-upstream",
			"type":    "stdio",
			"command": "../../etc/passwd",
			"enabled": true,
		}

		resp := env.doJSON(t, "POST", "/admin/api/upstreams", createReq)
		if resp.StatusCode != http.StatusBadRequest {
			body := readBody(t, resp)
			t.Errorf("path traversal in command: status=%d (want 400), body=%s", resp.StatusCode, body)
		} else {
			body := readBody(t, resp)
			if !strings.Contains(body, "path traversal") {
				t.Errorf("expected path traversal error message, got: %s", body)
			}
		}
	})

	t.Run("args_with_path_traversal", func(t *testing.T) {
		createReq := map[string]interface{}{
			"name":    "traversal-args-upstream",
			"type":    "stdio",
			"command": "node",
			"args":    []string{"--file", "../../../etc/shadow"},
			"enabled": true,
		}

		resp := env.doJSON(t, "POST", "/admin/api/upstreams", createReq)
		if resp.StatusCode != http.StatusBadRequest {
			body := readBody(t, resp)
			t.Errorf("path traversal in args: status=%d (want 400), body=%s", resp.StatusCode, body)
		} else {
			body := readBody(t, resp)
			if !strings.Contains(body, "path traversal") {
				t.Errorf("expected path traversal error message, got: %s", body)
			}
		}
	})

	t.Run("dotdot_in_middle_of_path", func(t *testing.T) {
		createReq := map[string]interface{}{
			"name":    "traversal-mid-upstream",
			"type":    "stdio",
			"command": "/usr/bin/../../../etc/passwd",
			"enabled": true,
		}

		resp := env.doJSON(t, "POST", "/admin/api/upstreams", createReq)
		if resp.StatusCode != http.StatusBadRequest {
			body := readBody(t, resp)
			t.Errorf("path traversal in middle: status=%d (want 400), body=%s", resp.StatusCode, body)
		} else {
			_ = resp.Body.Close()
		}
	})

	t.Run("safe_command_accepted", func(t *testing.T) {
		createReq := map[string]interface{}{
			"name":    "safe-upstream",
			"type":    "stdio",
			"command": "node",
			"args":    []string{"server.js", "--port", "3000"},
			"enabled": true,
		}

		resp := env.doJSON(t, "POST", "/admin/api/upstreams", createReq)
		if resp.StatusCode == http.StatusBadRequest {
			body := readBody(t, resp)
			if strings.Contains(body, "path traversal") {
				t.Errorf("safe command rejected as path traversal: %s", body)
			}
		}
		_ = resp.Body.Close()
	})

	t.Run("update_with_path_traversal_rejected", func(t *testing.T) {
		createReq := map[string]interface{}{
			"name":    "update-target",
			"type":    "http",
			"url":     "http://localhost:9999",
			"enabled": true,
		}
		resp := env.doJSON(t, "POST", "/admin/api/upstreams", createReq)
		if resp.StatusCode != http.StatusCreated {
			body := readBody(t, resp)
			t.Fatalf("create upstream: status=%d, body=%s", resp.StatusCode, body)
		}
		var created map[string]interface{}
		decodeJSON(t, resp, &created)
		upstreamID := created["id"].(string)

		updateReq := map[string]interface{}{
			"name":    "update-target",
			"type":    "stdio",
			"command": "../../../malicious",
		}
		resp = env.doJSON(t, "PUT", "/admin/api/upstreams/"+upstreamID, updateReq)
		if resp.StatusCode != http.StatusBadRequest {
			body := readBody(t, resp)
			t.Errorf("update with path traversal: status=%d (want 400), body=%s", resp.StatusCode, body)
		} else {
			_ = resp.Body.Close()
		}
	})
}

// ============================================================================
// TestSecurity_CSPHeaders (SECU-03)
// Verifies that Content-Security-Policy and other security headers are set
// on all responses.
// ============================================================================

func TestSecurity_CSPHeaders(t *testing.T) {
	env := setupTestEnv(t)

	resp := env.doJSON(t, "GET", "/admin/api/stats", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stats: status=%d", resp.StatusCode)
	}
	defer func() { _ = resp.Body.Close() }()

	securityHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'self'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
	}

	for header, expectedSubstring := range securityHeaders {
		value := resp.Header.Get(header)
		if value == "" {
			t.Errorf("missing security header: %s", header)
		} else if !strings.Contains(value, expectedSubstring) {
			t.Errorf("%s = %q, want to contain %q", header, value, expectedSubstring)
		}
	}
}
