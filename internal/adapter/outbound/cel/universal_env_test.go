package cel

import (
	"testing"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// compileAndEval is a helper that compiles and evaluates a CEL expression
// against a universal activation built from the given EvaluationContext.
func compileAndEval(t *testing.T, expr string, evalCtx policy.EvaluationContext) bool {
	t.Helper()
	env, err := NewUniversalPolicyEnvironment()
	if err != nil {
		t.Fatalf("NewUniversalPolicyEnvironment() error: %v", err)
	}

	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("Compile(%q) error: %v", expr, issues.Err())
	}

	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		t.Fatalf("Program() error: %v", err)
	}

	activation := BuildUniversalActivation(evalCtx)
	result, _, err := prg.Eval(activation)
	if err != nil {
		t.Fatalf("Eval(%q) error: %v", expr, err)
	}

	b, ok := result.Value().(bool)
	if !ok {
		t.Fatalf("Eval(%q) returned %T, want bool", expr, result.Value())
	}
	return b
}

// baseMCPContext returns an EvaluationContext with typical MCP tool call fields populated.
func baseMCPContext() policy.EvaluationContext {
	return policy.EvaluationContext{
		ToolName:      "read_file",
		ToolArguments: map[string]interface{}{"path": "/etc/passwd"},
		UserRoles:     []string{"admin", "user"},
		SessionID:     "sess-1",
		IdentityID:    "id-1",
		IdentityName:  "alice",
		RequestTime:   time.Now(),
		ActionType:    "tool_call",
		ActionName:    "read_file",
		Protocol:      "mcp",
		Gateway:       "mcp-gateway",
	}
}

func TestUniversalEnv_BackwardCompatible_ToolName(t *testing.T) {
	ctx := baseMCPContext()
	if !compileAndEval(t, `tool_name == "read_file"`, ctx) {
		t.Error("expected tool_name == 'read_file' to be true")
	}
	if compileAndEval(t, `tool_name == "write_file"`, ctx) {
		t.Error("expected tool_name == 'write_file' to be false")
	}
}

func TestUniversalEnv_BackwardCompatible_UserRoles(t *testing.T) {
	ctx := baseMCPContext()
	if !compileAndEval(t, `"admin" in user_roles`, ctx) {
		t.Error("expected 'admin' in user_roles to be true")
	}
	if compileAndEval(t, `"superadmin" in user_roles`, ctx) {
		t.Error("expected 'superadmin' in user_roles to be false")
	}
}

func TestUniversalEnv_BackwardCompatible_Glob(t *testing.T) {
	ctx := baseMCPContext()
	if !compileAndEval(t, `glob("read_*", tool_name)`, ctx) {
		t.Error("expected glob('read_*', tool_name) to be true")
	}
	if compileAndEval(t, `glob("write_*", tool_name)`, ctx) {
		t.Error("expected glob('write_*', tool_name) to be false")
	}
}

func TestUniversalEnv_ActionType(t *testing.T) {
	ctx := baseMCPContext()
	if !compileAndEval(t, `action_type == "tool_call"`, ctx) {
		t.Error("expected action_type == 'tool_call' to be true")
	}
	if compileAndEval(t, `action_type == "http_request"`, ctx) {
		t.Error("expected action_type == 'http_request' to be false")
	}
}

func TestUniversalEnv_ActionName(t *testing.T) {
	ctx := baseMCPContext()
	// action_name should equal tool_name for MCP tool calls
	if !compileAndEval(t, `action_name == "read_file"`, ctx) {
		t.Error("expected action_name == 'read_file' to be true")
	}
	if !compileAndEval(t, `action_name == tool_name`, ctx) {
		t.Error("expected action_name == tool_name to be true")
	}
}

func TestUniversalEnv_Protocol(t *testing.T) {
	ctx := baseMCPContext()
	if !compileAndEval(t, `protocol == "mcp"`, ctx) {
		t.Error("expected protocol == 'mcp' to be true")
	}
	if compileAndEval(t, `protocol == "http"`, ctx) {
		t.Error("expected protocol == 'http' to be false")
	}
}

func TestUniversalEnv_DestDomain(t *testing.T) {
	ctx := baseMCPContext()
	ctx.DestDomain = "evil.com"
	if !compileAndEval(t, `dest_domain == "evil.com"`, ctx) {
		t.Error("expected dest_domain == 'evil.com' to be true")
	}
	if compileAndEval(t, `dest_domain == "safe.com"`, ctx) {
		t.Error("expected dest_domain == 'safe.com' to be false")
	}
}

func TestUniversalEnv_DestIPInCIDR(t *testing.T) {
	ctx := baseMCPContext()

	t.Run("ip_in_range", func(t *testing.T) {
		ctx.DestIP = "10.1.2.3"
		if !compileAndEval(t, `dest_ip_in_cidr(dest_ip, "10.0.0.0/8")`, ctx) {
			t.Error("expected 10.1.2.3 to be in 10.0.0.0/8")
		}
	})

	t.Run("ip_not_in_range", func(t *testing.T) {
		ctx.DestIP = "192.168.1.1"
		if compileAndEval(t, `dest_ip_in_cidr(dest_ip, "10.0.0.0/8")`, ctx) {
			t.Error("expected 192.168.1.1 to NOT be in 10.0.0.0/8")
		}
	})

	t.Run("invalid_ip", func(t *testing.T) {
		ctx.DestIP = "not-an-ip"
		if compileAndEval(t, `dest_ip_in_cidr(dest_ip, "10.0.0.0/8")`, ctx) {
			t.Error("expected invalid IP to return false")
		}
	})

	t.Run("invalid_cidr", func(t *testing.T) {
		ctx.DestIP = "10.1.2.3"
		if compileAndEval(t, `dest_ip_in_cidr(dest_ip, "not-a-cidr")`, ctx) {
			t.Error("expected invalid CIDR to return false")
		}
	})
}

func TestUniversalEnv_DestDomainMatches(t *testing.T) {
	ctx := baseMCPContext()

	t.Run("match", func(t *testing.T) {
		ctx.DestDomain = "api.evil.com"
		if !compileAndEval(t, `dest_domain_matches(dest_domain, "*.evil.com")`, ctx) {
			t.Error("expected api.evil.com to match *.evil.com")
		}
	})

	t.Run("no_match", func(t *testing.T) {
		ctx.DestDomain = "safe.com"
		if compileAndEval(t, `dest_domain_matches(dest_domain, "*.evil.com")`, ctx) {
			t.Error("expected safe.com to NOT match *.evil.com")
		}
	})
}

func TestDomainMatchesWildcard(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		pattern string
		want    bool
	}{
		// Exact match
		{name: "exact_match", domain: "evil.com", pattern: "evil.com", want: true},
		{name: "exact_no_match", domain: "notevil.com", pattern: "evil.com", want: false},

		// Wildcard: single-level subdomain
		{name: "wildcard_single_level", domain: "api.evil.com", pattern: "*.evil.com", want: true},
		{name: "wildcard_hyphenated_single", domain: "evil.test-domain.invalid", pattern: "*.test-domain.invalid", want: true},

		// Wildcard: multi-level subdomains
		{name: "wildcard_multi_level", domain: "deep.sub.evil.com", pattern: "*.evil.com", want: true},
		{name: "wildcard_multi_level_hyphenated", domain: "sub.evil.test-domain.invalid", pattern: "*.test-domain.invalid", want: true},

		// Wildcard: bare domain should NOT match wildcard pattern
		{name: "wildcard_bare_no_match", domain: "evil.com", pattern: "*.evil.com", want: false},

		// Wildcard: completely different domain
		{name: "wildcard_wrong_domain", domain: "notevil.com", pattern: "*.evil.com", want: false},
		// Suffix collision guard: "evilevil.com" should not match "*.evil.com"
		{name: "wildcard_suffix_collision", domain: "evilevil.com", pattern: "*.evil.com", want: false},

		// T6.3 specific case: the bug that was failing
		{name: "t6_3_hyphenated_domain", domain: "evil.test-domain.invalid", pattern: "*.test-domain.invalid", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domainMatchesWildcard(tt.domain, tt.pattern)
			if got != tt.want {
				t.Errorf("domainMatchesWildcard(%q, %q) = %v, want %v", tt.domain, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestDestDomainMatchesCEL_HyphenatedDomain verifies the T6.3 bug fix via the full CEL path.
func TestDestDomainMatchesCEL_HyphenatedDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		pattern string
		want    bool
	}{
		{"hyphenated single level", "evil.test-domain.invalid", "*.test-domain.invalid", true},
		{"hyphenated multi level", "sub.evil.test-domain.invalid", "*.test-domain.invalid", true},
		{"exact hyphenated", "test-domain.invalid", "test-domain.invalid", true},
		{"bare domain no match", "test-domain.invalid", "*.test-domain.invalid", false},
		{"suffix collision guard", "eviltest-domain.invalid", "*.test-domain.invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := baseMCPContext()
			ctx.DestDomain = tt.domain
			expr := `dest_domain_matches(dest_domain, "` + tt.pattern + `")`
			got := compileAndEval(t, expr, ctx)
			if got != tt.want {
				t.Errorf("CEL %s: got %v, want %v", expr, got, tt.want)
			}
		})
	}
}

func TestUniversalEnv_ActionArg(t *testing.T) {
	ctx := baseMCPContext()
	ctx.ToolArguments = map[string]interface{}{
		"path": "/etc/passwd",
		"mode": "read",
	}

	if !compileAndEval(t, `action_arg(arguments, "path") == "/etc/passwd"`, ctx) {
		t.Error("expected action_arg(arguments, 'path') == '/etc/passwd' to be true")
	}
}

func TestUniversalEnv_ActionArgContains(t *testing.T) {
	ctx := baseMCPContext()
	ctx.ToolArguments = map[string]interface{}{
		"query":    "SELECT * FROM users WHERE password = 'secret'",
		"database": "production",
	}

	t.Run("contains_match", func(t *testing.T) {
		if !compileAndEval(t, `action_arg_contains(arguments, "password")`, ctx) {
			t.Error("expected action_arg_contains(arguments, 'password') to be true")
		}
	})

	t.Run("no_match", func(t *testing.T) {
		if compileAndEval(t, `action_arg_contains(arguments, "DROP TABLE")`, ctx) {
			t.Error("expected action_arg_contains(arguments, 'DROP TABLE') to be false")
		}
	})
}

func TestUniversalEnv_CrossProtocol_CommandExec(t *testing.T) {
	ctx := policy.EvaluationContext{
		ToolName:      "",
		ToolArguments: map[string]interface{}{"flags": "-rf /"},
		UserRoles:     []string{"operator"},
		SessionID:     "sess-2",
		IdentityID:    "id-2",
		IdentityName:  "bob",
		RequestTime:   time.Now(),
		ActionType:    "command_exec",
		ActionName:    "rm",
		Protocol:      "runtime",
		Gateway:       "runtime",
		DestCommand:   "rm",
	}

	if !compileAndEval(t, `action_type == "command_exec" && dest_command == "rm"`, ctx) {
		t.Error("expected command_exec && dest_command == 'rm' to be true")
	}
}

func TestUniversalEnv_CrossProtocol_FileAccess(t *testing.T) {
	ctx := policy.EvaluationContext{
		ToolName:      "",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"reader"},
		SessionID:     "sess-3",
		IdentityID:    "id-3",
		IdentityName:  "charlie",
		RequestTime:   time.Now(),
		ActionType:    "file_access",
		ActionName:    "read",
		Protocol:      "runtime",
		Gateway:       "runtime",
		DestPath:      "/etc/shadow",
	}

	if !compileAndEval(t, `action_type == "file_access" && dest_path.startsWith("/etc")`, ctx) {
		t.Error("expected file_access && dest_path starts with /etc to be true")
	}
}

func TestUniversalEnv_CrossProtocol_FrameworkRestriction(t *testing.T) {
	ctx := policy.EvaluationContext{
		ToolName:      "",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"agent"},
		SessionID:     "sess-4",
		IdentityID:    "id-4",
		IdentityName:  "agent-1",
		RequestTime:   time.Now(),
		ActionType:    "http_request",
		ActionName:    "GET",
		Protocol:      "http",
		Framework:     "crewai",
		Gateway:       "http-gateway",
		DestURL:       "https://api.example.com/data",
		DestDomain:    "api.example.com",
		DestScheme:    "https",
		DestPath:      "/data",
	}

	if !compileAndEval(t, `framework == "crewai" && action_type == "http_request"`, ctx) {
		t.Error("expected crewai && http_request to be true")
	}
}

func TestUniversalEnv_DefaultFilling(t *testing.T) {
	// Legacy context with only old fields populated - defaults should kick in
	ctx := policy.EvaluationContext{
		ToolName:      "read_file",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"admin"},
		SessionID:     "sess-1",
		IdentityID:    "id-1",
		IdentityName:  "alice",
		RequestTime:   time.Now(),
		// ActionType, ActionName, Protocol are all empty
	}

	// fillDefaults should set ActionType="tool_call", ActionName="read_file", Protocol="mcp"
	if !compileAndEval(t, `action_type == "tool_call"`, ctx) {
		t.Error("expected default action_type to be 'tool_call'")
	}
	if !compileAndEval(t, `action_name == "read_file"`, ctx) {
		t.Error("expected default action_name to be tool_name value")
	}
	if !compileAndEval(t, `protocol == "mcp"`, ctx) {
		t.Error("expected default protocol to be 'mcp'")
	}
}

func TestCEL_SessionCallCount(t *testing.T) {
	ctx := baseMCPContext()
	ctx.SessionCallCount = 150
	if !compileAndEval(t, `session_call_count > 100`, ctx) {
		t.Error("expected session_call_count > 100 to be true (150)")
	}
	if compileAndEval(t, `session_call_count > 200`, ctx) {
		t.Error("expected session_call_count > 200 to be false (150)")
	}
}

func TestCEL_SessionWriteCount(t *testing.T) {
	ctx := baseMCPContext()
	ctx.SessionWriteCount = 15
	if !compileAndEval(t, `session_write_count > 10`, ctx) {
		t.Error("expected session_write_count > 10 to be true (15)")
	}
	if compileAndEval(t, `session_write_count > 20`, ctx) {
		t.Error("expected session_write_count > 20 to be false (15)")
	}
}

func TestCEL_SessionDeleteCount(t *testing.T) {
	ctx := baseMCPContext()
	ctx.SessionDeleteCount = 3
	if compileAndEval(t, `session_delete_count > 5`, ctx) {
		t.Error("expected session_delete_count > 5 to be false (3)")
	}
	if !compileAndEval(t, `session_delete_count <= 5`, ctx) {
		t.Error("expected session_delete_count <= 5 to be true (3)")
	}
}

func TestCEL_SessionDurationSeconds(t *testing.T) {
	ctx := baseMCPContext()
	ctx.SessionDurationSeconds = 7200
	if !compileAndEval(t, `session_duration_seconds > 3600`, ctx) {
		t.Error("expected session_duration_seconds > 3600 to be true (7200)")
	}
	if compileAndEval(t, `session_duration_seconds > 10000`, ctx) {
		t.Error("expected session_duration_seconds > 10000 to be false (7200)")
	}
}

func TestCEL_SessionVariables_DefaultZero(t *testing.T) {
	// Empty EvaluationContext — session variables should all be 0
	ctx := baseMCPContext()
	// Session fields not set — default to 0

	if compileAndEval(t, `session_call_count > 0`, ctx) {
		t.Error("expected session_call_count to default to 0")
	}
	if compileAndEval(t, `session_write_count > 0`, ctx) {
		t.Error("expected session_write_count to default to 0")
	}
	if compileAndEval(t, `session_delete_count > 0`, ctx) {
		t.Error("expected session_delete_count to default to 0")
	}
	if compileAndEval(t, `session_duration_seconds > 0`, ctx) {
		t.Error("expected session_duration_seconds to default to 0")
	}
}

func TestCEL_SessionCombinedRule(t *testing.T) {
	ctx := baseMCPContext()
	ctx.SessionCallCount = 200
	// baseMCPContext already has user_roles = ["admin", "user"]
	if !compileAndEval(t, `session_call_count > 100 && user_roles.exists(r, r == "admin")`, ctx) {
		t.Error("expected combined session + role rule to be true")
	}

	// Same rule but with non-admin roles
	ctx2 := baseMCPContext()
	ctx2.SessionCallCount = 200
	ctx2.UserRoles = []string{"viewer"}
	if compileAndEval(t, `session_call_count > 100 && user_roles.exists(r, r == "admin")`, ctx2) {
		t.Error("expected combined session + role rule to be false (no admin role)")
	}
}

func TestBuildUniversalActivation_NilSafety(t *testing.T) {
	// Context with nil maps and slices should not panic
	ctx := policy.EvaluationContext{
		ToolName:    "test",
		RequestTime: time.Now(),
		// ToolArguments and UserRoles are nil
	}

	activation := BuildUniversalActivation(ctx)

	// Should have non-nil values for maps and slices
	if activation["tool_args"] == nil {
		t.Error("tool_args should not be nil")
	}
	if activation["user_roles"] == nil {
		t.Error("user_roles should not be nil")
	}
	if activation["arguments"] == nil {
		t.Error("arguments should not be nil")
	}
	if activation["identity_roles"] == nil {
		t.Error("identity_roles should not be nil")
	}
}

// compileAndEvalInt is a helper that compiles and evaluates a CEL expression
// returning an int64 result.
func compileAndEvalInt(t *testing.T, expr string, evalCtx policy.EvaluationContext) int64 {
	t.Helper()
	env, err := NewUniversalPolicyEnvironment()
	if err != nil {
		t.Fatalf("NewUniversalPolicyEnvironment() error: %v", err)
	}

	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		t.Fatalf("Compile(%q) error: %v", expr, issues.Err())
	}

	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		t.Fatalf("Program() error: %v", err)
	}

	activation := BuildUniversalActivation(evalCtx)
	result, _, err := prg.Eval(activation)
	if err != nil {
		t.Fatalf("Eval(%q) error: %v", expr, err)
	}

	v, ok := result.Value().(int64)
	if !ok {
		t.Fatalf("Eval(%q) returned %T, want int64", expr, result.Value())
	}
	return v
}

// baseSessionContext returns an EvaluationContext with a populated session action history.
// Simulated session: read_file, write_file, read_file, send_email
func baseSessionContext() policy.EvaluationContext {
	now := time.Now()
	ctx := baseMCPContext()
	ctx.SessionActionHistory = []policy.SessionActionRecord{
		{ToolName: "read_file", CallType: "read", Timestamp: now.Add(-30 * time.Second), ArgKeys: []string{"path"}},
		{ToolName: "write_file", CallType: "write", Timestamp: now.Add(-20 * time.Second), ArgKeys: []string{"path", "content"}},
		{ToolName: "read_file", CallType: "read", Timestamp: now.Add(-10 * time.Second), ArgKeys: []string{"path"}},
		{ToolName: "send_email", CallType: "other", Timestamp: now.Add(-5 * time.Second), ArgKeys: []string{"to", "body"}},
	}
	ctx.SessionActionSet = map[string]bool{"read_file": true, "write_file": true, "send_email": true}
	ctx.SessionArgKeySet = map[string]bool{"path": true, "content": true, "to": true, "body": true}
	return ctx
}

func TestSessionCELFunctions(t *testing.T) {
	t.Run("session_count", func(t *testing.T) {
		ctx := baseSessionContext()
		// Two "read" call types (both read_file calls)
		v := compileAndEvalInt(t, `session_count(session_action_history, "read")`, ctx)
		if v != 2 {
			t.Errorf("session_count(read) = %d, want 2", v)
		}
	})

	t.Run("session_count_write", func(t *testing.T) {
		ctx := baseSessionContext()
		v := compileAndEvalInt(t, `session_count(session_action_history, "write")`, ctx)
		if v != 1 {
			t.Errorf("session_count(write) = %d, want 1", v)
		}
	})

	t.Run("session_count_for", func(t *testing.T) {
		ctx := baseSessionContext()
		v := compileAndEvalInt(t, `session_count_for(session_action_history, "read_file")`, ctx)
		if v != 2 {
			t.Errorf("session_count_for(read_file) = %d, want 2", v)
		}
	})

	t.Run("session_count_window", func(t *testing.T) {
		ctx := baseSessionContext()
		// Only the -10s read_file is within 15s window
		v := compileAndEvalInt(t, `session_count_window(session_action_history, "read_file", 15)`, ctx)
		if v != 1 {
			t.Errorf("session_count_window(read_file, 15) = %d, want 1", v)
		}
	})

	t.Run("session_count_window_all", func(t *testing.T) {
		ctx := baseSessionContext()
		// Both read_file calls are within 60s window
		v := compileAndEvalInt(t, `session_count_window(session_action_history, "read_file", 60)`, ctx)
		if v != 2 {
			t.Errorf("session_count_window(read_file, 60) = %d, want 2", v)
		}
	})

	t.Run("session_has_action_true", func(t *testing.T) {
		ctx := baseSessionContext()
		if !compileAndEval(t, `session_has_action(session_action_set, "write_file")`, ctx) {
			t.Error("expected session_has_action(write_file) to be true")
		}
	})

	t.Run("session_has_action_false", func(t *testing.T) {
		ctx := baseSessionContext()
		if compileAndEval(t, `session_has_action(session_action_set, "delete_file")`, ctx) {
			t.Error("expected session_has_action(delete_file) to be false")
		}
	})

	t.Run("session_has_arg_true", func(t *testing.T) {
		ctx := baseSessionContext()
		if !compileAndEval(t, `session_has_arg(session_arg_key_set, "content")`, ctx) {
			t.Error("expected session_has_arg(content) to be true")
		}
	})

	t.Run("session_has_arg_false", func(t *testing.T) {
		ctx := baseSessionContext()
		if compileAndEval(t, `session_has_arg(session_arg_key_set, "password")`, ctx) {
			t.Error("expected session_has_arg(password) to be false")
		}
	})

	t.Run("session_has_arg_in_true", func(t *testing.T) {
		ctx := baseSessionContext()
		if !compileAndEval(t, `session_has_arg_in(session_action_history, "content", "write_file")`, ctx) {
			t.Error("expected session_has_arg_in(content, write_file) to be true")
		}
	})

	t.Run("session_has_arg_in_false", func(t *testing.T) {
		ctx := baseSessionContext()
		if compileAndEval(t, `session_has_arg_in(session_action_history, "content", "read_file")`, ctx) {
			t.Error("expected session_has_arg_in(content, read_file) to be false")
		}
	})

	t.Run("session_sequence_true", func(t *testing.T) {
		ctx := baseSessionContext()
		if !compileAndEval(t, `session_sequence(session_action_history, "read_file", "send_email")`, ctx) {
			t.Error("expected session_sequence(read_file, send_email) to be true")
		}
	})

	t.Run("session_sequence_false", func(t *testing.T) {
		ctx := baseSessionContext()
		// send_email is the last action; read_file never appears after it
		if compileAndEval(t, `session_sequence(session_action_history, "send_email", "read_file")`, ctx) {
			t.Error("expected session_sequence(send_email, read_file) to be false")
		}
	})

	t.Run("session_time_since_action", func(t *testing.T) {
		ctx := baseSessionContext()
		// send_email was ~5s ago, so time_since should be < 10
		if !compileAndEval(t, `session_time_since_action(session_action_history, "send_email") < 10`, ctx) {
			t.Error("expected session_time_since_action(send_email) < 10 to be true")
		}
	})

	t.Run("session_time_since_action_never", func(t *testing.T) {
		ctx := baseSessionContext()
		v := compileAndEvalInt(t, `session_time_since_action(session_action_history, "delete_file")`, ctx)
		if v != -1 {
			t.Errorf("session_time_since_action(delete_file) = %d, want -1", v)
		}
	})
}

func TestSessionCELFunctions_EmptyHistory(t *testing.T) {
	// No session history — functions should return safe defaults
	ctx := baseMCPContext()
	// SessionActionHistory, SessionActionSet, SessionArgKeySet are nil

	t.Run("session_count_empty", func(t *testing.T) {
		v := compileAndEvalInt(t, `session_count(session_action_history, "read")`, ctx)
		if v != 0 {
			t.Errorf("session_count(read) on empty = %d, want 0", v)
		}
	})

	t.Run("session_has_action_empty", func(t *testing.T) {
		if compileAndEval(t, `session_has_action(session_action_set, "read_file")`, ctx) {
			t.Error("expected session_has_action to be false on empty set")
		}
	})

	t.Run("session_sequence_empty", func(t *testing.T) {
		if compileAndEval(t, `session_sequence(session_action_history, "a", "b")`, ctx) {
			t.Error("expected session_sequence to be false on empty history")
		}
	})
}
