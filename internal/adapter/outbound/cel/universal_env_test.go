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
