package sentinelgate

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Client construction tests
// ---------------------------------------------------------------------------

func TestNewClient_Defaults(t *testing.T) {
	// Clear env vars that would override defaults.
	t.Setenv("SENTINELGATE_SERVER_ADDR", "")
	t.Setenv("SENTINELGATE_API_KEY", "")
	t.Setenv("SENTINELGATE_PROTOCOL", "")
	t.Setenv("SENTINELGATE_FAIL_MODE", "")
	t.Setenv("SENTINELGATE_TIMEOUT", "")
	t.Setenv("SENTINELGATE_CACHE_TTL", "")
	t.Setenv("SENTINELGATE_CACHE_MAX_SIZE", "")
	t.Setenv("SENTINELGATE_IDENTITY_NAME", "")
	t.Setenv("SENTINELGATE_IDENTITY_ROLES", "")

	c := NewClient()

	if c.serverAddr != "" {
		t.Errorf("expected empty serverAddr, got %q", c.serverAddr)
	}
	if c.apiKey != "" {
		t.Errorf("expected empty apiKey, got %q", c.apiKey)
	}
	if c.defaultProtocol != "sdk" {
		t.Errorf("expected defaultProtocol=sdk, got %q", c.defaultProtocol)
	}
	if c.failMode != "open" {
		t.Errorf("expected failMode=open, got %q", c.failMode)
	}
	if c.timeout != 5*time.Second {
		t.Errorf("expected timeout=5s, got %v", c.timeout)
	}
	if c.cacheTTL != 5*time.Second {
		t.Errorf("expected cacheTTL=5s, got %v", c.cacheTTL)
	}
	if c.cacheMaxSize != 1000 {
		t.Errorf("expected cacheMaxSize=1000, got %d", c.cacheMaxSize)
	}
	if c.httpClient == nil {
		t.Error("expected httpClient to be non-nil")
	}
}

func TestNewClient_AllOptionsApplied(t *testing.T) {
	t.Setenv("SENTINELGATE_SERVER_ADDR", "")
	t.Setenv("SENTINELGATE_API_KEY", "")
	t.Setenv("SENTINELGATE_PROTOCOL", "")
	t.Setenv("SENTINELGATE_FAIL_MODE", "")
	t.Setenv("SENTINELGATE_TIMEOUT", "")
	t.Setenv("SENTINELGATE_CACHE_TTL", "")
	t.Setenv("SENTINELGATE_CACHE_MAX_SIZE", "")
	t.Setenv("SENTINELGATE_IDENTITY_NAME", "")
	t.Setenv("SENTINELGATE_IDENTITY_ROLES", "")

	customHTTP := &http.Client{Timeout: 99 * time.Second}

	c := NewClient(
		WithServerAddr("https://sg.example.com"),
		WithAPIKey("my-key"),
		WithDefaultProtocol("a2a"),
		WithFailMode("closed"),
		WithTimeout(15*time.Second),
		WithCacheTTL(30*time.Second),
		WithCacheMaxSize(500),
		WithHTTPClient(customHTTP),
		WithIdentityName("bot-1"),
		WithIdentityRoles([]string{"admin", "reader"}),
	)

	if c.serverAddr != "https://sg.example.com" {
		t.Errorf("serverAddr: got %q", c.serverAddr)
	}
	if c.apiKey != "my-key" {
		t.Errorf("apiKey: got %q", c.apiKey)
	}
	if c.defaultProtocol != "a2a" {
		t.Errorf("defaultProtocol: got %q", c.defaultProtocol)
	}
	if c.failMode != "closed" {
		t.Errorf("failMode: got %q", c.failMode)
	}
	if c.timeout != 15*time.Second {
		t.Errorf("timeout: got %v", c.timeout)
	}
	if c.cacheTTL != 30*time.Second {
		t.Errorf("cacheTTL: got %v", c.cacheTTL)
	}
	if c.cacheMaxSize != 500 {
		t.Errorf("cacheMaxSize: got %d", c.cacheMaxSize)
	}
	if c.httpClient != customHTTP {
		t.Error("expected custom httpClient to be set")
	}
	if c.identityName != "bot-1" {
		t.Errorf("identityName: got %q", c.identityName)
	}
	if len(c.identityRoles) != 2 || c.identityRoles[0] != "admin" || c.identityRoles[1] != "reader" {
		t.Errorf("identityRoles: got %v", c.identityRoles)
	}
}

func TestNewClient_OptionsOverrideEnv(t *testing.T) {
	t.Setenv("SENTINELGATE_SERVER_ADDR", "http://env-server")
	t.Setenv("SENTINELGATE_API_KEY", "env-key")
	t.Setenv("SENTINELGATE_FAIL_MODE", "closed")

	c := NewClient(
		WithServerAddr("http://opt-server"),
		WithAPIKey("opt-key"),
		WithFailMode("open"),
	)

	if c.serverAddr != "http://opt-server" {
		t.Errorf("expected option to override env, got serverAddr=%q", c.serverAddr)
	}
	if c.apiKey != "opt-key" {
		t.Errorf("expected option to override env, got apiKey=%q", c.apiKey)
	}
	if c.failMode != "open" {
		t.Errorf("expected option to override env, got failMode=%q", c.failMode)
	}
}

func TestNewClient_DefaultHTTPClientTimeout(t *testing.T) {
	t.Setenv("SENTINELGATE_TIMEOUT", "")

	c := NewClient(WithTimeout(7 * time.Second))

	// When no custom httpClient is provided, the auto-created one should
	// use the configured timeout.
	if c.httpClient == nil {
		t.Fatal("httpClient should not be nil")
	}
	if c.httpClient.Timeout != 7*time.Second {
		t.Errorf("expected httpClient.Timeout=7s, got %v", c.httpClient.Timeout)
	}
}

func TestNewClient_CustomHTTPClientPreserved(t *testing.T) {
	custom := &http.Client{Timeout: 42 * time.Second}
	c := NewClient(WithHTTPClient(custom))

	// Custom http.Client must be used as-is; its timeout should NOT be
	// overwritten by WithTimeout.
	if c.httpClient != custom {
		t.Error("custom http.Client was not preserved")
	}
	if c.httpClient.Timeout != 42*time.Second {
		t.Errorf("custom timeout was overwritten, got %v", c.httpClient.Timeout)
	}
}

// ---------------------------------------------------------------------------
// Option function tests
// ---------------------------------------------------------------------------

func TestWithServerAddr(t *testing.T) {
	c := &Client{}
	opt := WithServerAddr("http://test:1234")
	opt(c)
	if c.serverAddr != "http://test:1234" {
		t.Errorf("WithServerAddr: got %q", c.serverAddr)
	}
}

func TestWithAPIKey(t *testing.T) {
	c := &Client{}
	opt := WithAPIKey("secret")
	opt(c)
	if c.apiKey != "secret" {
		t.Errorf("WithAPIKey: got %q", c.apiKey)
	}
}

func TestWithDefaultProtocol(t *testing.T) {
	c := &Client{}
	opt := WithDefaultProtocol("mcp")
	opt(c)
	if c.defaultProtocol != "mcp" {
		t.Errorf("WithDefaultProtocol: got %q", c.defaultProtocol)
	}
}

func TestWithFailMode(t *testing.T) {
	c := &Client{}
	opt := WithFailMode("closed")
	opt(c)
	if c.failMode != "closed" {
		t.Errorf("WithFailMode: got %q", c.failMode)
	}
}

func TestWithCacheTTL(t *testing.T) {
	c := &Client{}
	opt := WithCacheTTL(60 * time.Second)
	opt(c)
	if c.cacheTTL != 60*time.Second {
		t.Errorf("WithCacheTTL: got %v", c.cacheTTL)
	}
}

func TestWithCacheMaxSize(t *testing.T) {
	c := &Client{}
	opt := WithCacheMaxSize(2000)
	opt(c)
	if c.cacheMaxSize != 2000 {
		t.Errorf("WithCacheMaxSize: got %d", c.cacheMaxSize)
	}
}

func TestWithIdentityName(t *testing.T) {
	c := &Client{}
	opt := WithIdentityName("my-agent")
	opt(c)
	if c.identityName != "my-agent" {
		t.Errorf("WithIdentityName: got %q", c.identityName)
	}
}

func TestWithIdentityRoles(t *testing.T) {
	c := &Client{}
	opt := WithIdentityRoles([]string{"a", "b"})
	opt(c)
	if len(c.identityRoles) != 2 || c.identityRoles[0] != "a" || c.identityRoles[1] != "b" {
		t.Errorf("WithIdentityRoles: got %v", c.identityRoles)
	}
}

// ---------------------------------------------------------------------------
// Error type tests
// ---------------------------------------------------------------------------

func TestSentinelGateError_ErrorMessage(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		err := &SentinelGateError{Code: "EVAL_001", Err: errors.New("bad input")}
		msg := err.Error()
		if msg != "sentinelgate [EVAL_001]: bad input" {
			t.Errorf("unexpected message: %s", msg)
		}
	})
	t.Run("without underlying error", func(t *testing.T) {
		err := &SentinelGateError{Code: "NET_FAIL"}
		msg := err.Error()
		if msg != "sentinelgate [NET_FAIL]" {
			t.Errorf("unexpected message: %s", msg)
		}
	})
}

func TestSentinelGateError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &SentinelGateError{Code: "X", Err: inner}
	if errors.Unwrap(err) != inner {
		t.Error("Unwrap did not return inner error")
	}
}

func TestPolicyDeniedError_Is(t *testing.T) {
	err := &PolicyDeniedError{RuleName: "r", Reason: "denied"}
	if !errors.Is(err, ErrPolicyDenied) {
		t.Error("expected Is(ErrPolicyDenied) == true")
	}
	if errors.Is(err, ErrApprovalTimeout) {
		t.Error("should not match ErrApprovalTimeout")
	}
}

func TestApprovalTimeoutError_Is(t *testing.T) {
	err := &ApprovalTimeoutError{RequestID: "req-1"}
	if !errors.Is(err, ErrApprovalTimeout) {
		t.Error("expected Is(ErrApprovalTimeout) == true")
	}
	if errors.Is(err, ErrPolicyDenied) {
		t.Error("should not match ErrPolicyDenied")
	}
}

func TestServerUnreachableError_Is(t *testing.T) {
	err := &ServerUnreachableError{Cause: errors.New("conn refused")}
	if !errors.Is(err, ErrServerUnreachable) {
		t.Error("expected Is(ErrServerUnreachable) == true")
	}
	if errors.Is(err, ErrPolicyDenied) {
		t.Error("should not match ErrPolicyDenied")
	}
}

func TestServerUnreachableError_ErrorMessage(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		err := &ServerUnreachableError{Cause: errors.New("timeout")}
		if err.Error() != "server unreachable: timeout" {
			t.Errorf("unexpected message: %s", err.Error())
		}
	})
	t.Run("without cause", func(t *testing.T) {
		err := &ServerUnreachableError{}
		if err.Error() != "server unreachable" {
			t.Errorf("unexpected message: %s", err.Error())
		}
	})
}

func TestServerUnreachableError_Unwrap(t *testing.T) {
	cause := errors.New("dns failure")
	err := &ServerUnreachableError{Cause: cause}
	if errors.Unwrap(err) != cause {
		t.Error("Unwrap did not return cause")
	}
}

// ---------------------------------------------------------------------------
// Decision constants
// ---------------------------------------------------------------------------

func TestDecisionConstants(t *testing.T) {
	if DecisionAllow != "allow" {
		t.Errorf("DecisionAllow: got %q", DecisionAllow)
	}
	if DecisionDeny != "deny" {
		t.Errorf("DecisionDeny: got %q", DecisionDeny)
	}
	if DecisionApprovalRequired != "approval_required" {
		t.Errorf("DecisionApprovalRequired: got %q", DecisionApprovalRequired)
	}
}

// ---------------------------------------------------------------------------
// buildCacheKey tests
// ---------------------------------------------------------------------------

func TestBuildCacheKey_Deterministic(t *testing.T) {
	t.Setenv("SENTINELGATE_SERVER_ADDR", "")
	t.Setenv("SENTINELGATE_API_KEY", "")

	c := NewClient()

	req := EvaluateRequest{
		ActionType: "tool_call",
		ActionName: "read_file",
		Arguments:  map[string]any{"path": "/tmp/test.txt"},
	}

	key1 := c.buildCacheKey(req)
	key2 := c.buildCacheKey(req)

	if key1 != key2 {
		t.Errorf("cache key not deterministic: %q vs %q", key1, key2)
	}
}

func TestBuildCacheKey_DiffersForDifferentActions(t *testing.T) {
	t.Setenv("SENTINELGATE_SERVER_ADDR", "")
	t.Setenv("SENTINELGATE_API_KEY", "")

	c := NewClient()

	req1 := EvaluateRequest{ActionType: "tool_call", ActionName: "read_file"}
	req2 := EvaluateRequest{ActionType: "tool_call", ActionName: "write_file"}

	if c.buildCacheKey(req1) == c.buildCacheKey(req2) {
		t.Error("different action names should produce different cache keys")
	}
}

func TestBuildCacheKey_DiffersForDifferentArguments(t *testing.T) {
	t.Setenv("SENTINELGATE_SERVER_ADDR", "")
	t.Setenv("SENTINELGATE_API_KEY", "")

	c := NewClient()

	req1 := EvaluateRequest{
		ActionType: "tool_call",
		ActionName: "read_file",
		Arguments:  map[string]any{"path": "/a"},
	}
	req2 := EvaluateRequest{
		ActionType: "tool_call",
		ActionName: "read_file",
		Arguments:  map[string]any{"path": "/b"},
	}

	if c.buildCacheKey(req1) == c.buildCacheKey(req2) {
		t.Error("different arguments should produce different cache keys")
	}
}

// ---------------------------------------------------------------------------
// isConnectionError tests
// ---------------------------------------------------------------------------

func TestIsConnectionError(t *testing.T) {
	t.Run("nil error is not connection error", func(t *testing.T) {
		if isConnectionError(nil) {
			t.Error("nil should not be a connection error")
		}
	})

	t.Run("SentinelGateError is not connection error", func(t *testing.T) {
		err := &SentinelGateError{Code: "HTTP_500", Err: errors.New("server error")}
		if isConnectionError(err) {
			t.Error("SentinelGateError should not be a connection error")
		}
	})

	t.Run("generic error is connection error", func(t *testing.T) {
		err := errors.New("connection refused")
		if !isConnectionError(err) {
			t.Error("generic error should be treated as connection error")
		}
	})
}
