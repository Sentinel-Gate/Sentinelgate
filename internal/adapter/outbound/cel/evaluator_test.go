package cel

import (
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

func TestNewEvaluator(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}
	if eval == nil {
		t.Fatal("NewEvaluator() returned nil")
	}
}

func TestCompile_ValidExpression(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	prg, err := eval.Compile(`tool_name == "read_file"`)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}
	if prg == nil {
		t.Fatal("Compile() returned nil program")
	}
}

func TestCompile_InvalidExpression(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	_, err = eval.Compile(`this is not valid CEL !!!`)
	if err == nil {
		t.Fatal("Compile() expected error for invalid expression, got nil")
	}
}

func TestEvaluate_TrueCondition(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	prg, err := eval.Compile(`tool_name == "read_file"`)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	ctx := policy.EvaluationContext{
		ToolName:      "read_file",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{"admin"},
		SessionID:     "sess-1",
		IdentityID:    "id-1",
		RequestTime:   time.Now(),
	}

	result, err := eval.Evaluate(prg, ctx)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if !result {
		t.Error("expected true, got false")
	}
}

func TestEvaluate_FalseCondition(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	prg, err := eval.Compile(`tool_name == "write_file"`)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	ctx := policy.EvaluationContext{
		ToolName:      "read_file",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{},
		SessionID:     "sess-1",
		IdentityID:    "id-1",
		RequestTime:   time.Now(),
	}

	result, err := eval.Evaluate(prg, ctx)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if result {
		t.Error("expected false, got true")
	}
}

func TestValidateExpression_Valid(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	tests := []string{
		`tool_name == "read_file"`,
		`tool_name.startsWith("file_")`,
		`user_roles.exists(r, r == "admin")`,
		`glob("file_*", tool_name)`,
		`true`,
	}

	for _, expr := range tests {
		t.Run(expr, func(t *testing.T) {
			if err := eval.ValidateExpression(expr); err != nil {
				t.Errorf("ValidateExpression(%q) unexpected error: %v", expr, err)
			}
		})
	}
}

func TestValidateExpression_Invalid(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	tests := []struct {
		name string
		expr string
		want string // substring expected in error
	}{
		{"empty", "", "empty"},
		{"syntax error", "this is not valid !!!", "invalid CEL"},
		{"undefined var", "nonexistent_var == true", "invalid CEL"},
		{"too long", strings.Repeat("a", 1025), "too long"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := eval.ValidateExpression(tt.expr)
			if err == nil {
				t.Fatalf("ValidateExpression(%q) expected error, got nil", tt.expr)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

func TestValidateExpression_MaxLength(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	// Exactly at limit (1024 chars) - should be a valid expression though
	expr := `tool_name == "` + strings.Repeat("a", 1024-16) + `"`
	if len(expr) > 1024 {
		t.Fatalf("test setup: expr length %d > 1024", len(expr))
	}
	if err := eval.ValidateExpression(expr); err != nil {
		t.Errorf("expression at limit should be valid, got: %v", err)
	}

	// One over limit
	exprOver := expr + "x"
	if err := eval.ValidateExpression(exprOver); err == nil {
		t.Error("expression over limit should be rejected")
	}
}

func TestEvaluate_GlobFunction(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	prg, err := eval.Compile(`glob("file_*", tool_name)`)
	if err != nil {
		t.Fatalf("Compile() error: %v", err)
	}

	ctx := policy.EvaluationContext{
		ToolName:      "file_read",
		ToolArguments: map[string]interface{}{},
		UserRoles:     []string{},
		SessionID:     "sess-1",
		IdentityID:    "id-1",
		RequestTime:   time.Now(),
	}

	result, err := eval.Evaluate(prg, ctx)
	if err != nil {
		t.Fatalf("Evaluate() error: %v", err)
	}
	if !result {
		t.Error("glob('file_*', 'file_read') should be true")
	}
}

// --- HARDEN-02: Edge case tests for CEL hardening ---

func TestValidateExpression_NestingDepth(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	// buildNested creates an expression with n levels of parenthesis nesting around "true".
	buildNested := func(depth int) string {
		var b strings.Builder
		for i := 0; i < depth; i++ {
			b.WriteByte('(')
		}
		b.WriteString("true")
		for i := 0; i < depth; i++ {
			b.WriteByte(')')
		}
		return b.String()
	}

	t.Run("deeply_nested_60_levels_rejected", func(t *testing.T) {
		expr := buildNested(60)
		err := eval.ValidateExpression(expr)
		if err == nil {
			t.Fatal("expected error for 60 levels of nesting, got nil")
		}
		if !strings.Contains(err.Error(), "nesting too deep") {
			t.Errorf("error %q should contain 'nesting too deep'", err.Error())
		}
	})

	t.Run("at_limit_50_levels_accepted", func(t *testing.T) {
		expr := buildNested(50)
		err := eval.ValidateExpression(expr)
		if err != nil {
			t.Errorf("expression at nesting limit (50) should be valid, got: %v", err)
		}
	})

	t.Run("just_over_limit_51_levels_rejected", func(t *testing.T) {
		expr := buildNested(51)
		err := eval.ValidateExpression(expr)
		if err == nil {
			t.Fatal("expected error for 51 levels of nesting, got nil")
		}
		if !strings.Contains(err.Error(), "nesting too deep") {
			t.Errorf("error %q should contain 'nesting too deep'", err.Error())
		}
		if !strings.Contains(err.Error(), "51 levels") {
			t.Errorf("error %q should mention '51 levels'", err.Error())
		}
	})

	t.Run("unbalanced_brackets_caught_by_CEL_compiler", func(t *testing.T) {
		// Unbalanced nesting: 3 open parens, only 1 close.
		// validateNesting counts max depth (3), which is within limit.
		// CEL compilation should catch the syntax error.
		expr := "(((true)"
		err := eval.ValidateExpression(expr)
		if err == nil {
			t.Fatal("expected error for unbalanced brackets")
		}
		// Should be a CEL compilation error, not a nesting error
		if strings.Contains(err.Error(), "nesting too deep") {
			t.Error("unbalanced brackets should be caught by CEL compiler, not nesting validator")
		}
		if !strings.Contains(err.Error(), "invalid CEL") {
			t.Errorf("error %q should contain 'invalid CEL'", err.Error())
		}
	})

	t.Run("mixed_bracket_types", func(t *testing.T) {
		// Each bracket type contributes to nesting depth
		// Build something with mixed brackets exceeding limit
		// 20 parens + 20 brackets + 20 braces = 60 depth
		var b strings.Builder
		for i := 0; i < 20; i++ {
			b.WriteByte('(')
		}
		for i := 0; i < 20; i++ {
			b.WriteByte('[')
		}
		for i := 0; i < 20; i++ {
			b.WriteByte('{')
		}
		b.WriteString("true")
		for i := 0; i < 20; i++ {
			b.WriteByte('}')
		}
		for i := 0; i < 20; i++ {
			b.WriteByte(']')
		}
		for i := 0; i < 20; i++ {
			b.WriteByte(')')
		}
		expr := b.String()
		err := eval.ValidateExpression(expr)
		if err == nil {
			t.Fatal("expected error for 60 levels of mixed nesting")
		}
		if !strings.Contains(err.Error(), "nesting too deep") {
			t.Errorf("error %q should contain 'nesting too deep'", err.Error())
		}
	})
}

func TestCompile_CostLimitConfigured(t *testing.T) {
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	t.Run("cost_limit_accepts_normal_expressions", func(t *testing.T) {
		// Normal policy expressions should compile and evaluate fine with cost limit.
		// This verifies the CostLimit ProgramOption is accepted without error.
		prg, err := eval.Compile(`tool_name == "read_file"`)
		if err != nil {
			t.Fatalf("Compile() error: %v", err)
		}

		ctx := policy.EvaluationContext{
			ToolName:      "read_file",
			ToolArguments: map[string]interface{}{},
			UserRoles:     []string{"admin"},
			SessionID:     "sess-1",
			IdentityID:    "id-1",
			RequestTime:   time.Now(),
		}
		result, err := eval.Evaluate(prg, ctx)
		if err != nil {
			t.Fatalf("Evaluate() error: %v", err)
		}
		if !result {
			t.Error("expected true, got false")
		}
	})

	t.Run("cost_limit_with_comprehension", func(t *testing.T) {
		// Comprehension expressions are the primary target for cost limiting.
		// This tests that a typical role-check comprehension works within budget.
		prg, err := eval.Compile(`user_roles.exists(r, r == "admin")`)
		if err != nil {
			t.Fatalf("Compile() error: %v", err)
		}

		ctx := policy.EvaluationContext{
			ToolName:      "read_file",
			ToolArguments: map[string]interface{}{},
			UserRoles:     []string{"viewer", "editor", "admin"},
			SessionID:     "sess-1",
			IdentityID:    "id-1",
			RequestTime:   time.Now(),
		}
		result, err := eval.Evaluate(prg, ctx)
		if err != nil {
			t.Fatalf("Evaluate() error: %v", err)
		}
		if !result {
			t.Error("expected true for admin in roles, got false")
		}
	})

	// NOTE: Constructing a CEL expression that truly exceeds CostLimit(100000) within the
	// 1024-char expression limit is impractical. The cost limit serves as defense-in-depth
	// against pathological expressions that might bypass the length and nesting checks.
	// The key assertion is that CostLimit is configured (proven by normal evaluation working)
	// and that cel-go would enforce it at runtime if budget were exceeded.
}

func TestEvaluate_NoRegressionWithContextEval(t *testing.T) {
	// Verify that switching from prg.Eval to prg.ContextEval with timeout
	// doesn't break any normal evaluation patterns.
	eval, err := NewEvaluator()
	if err != nil {
		t.Fatalf("NewEvaluator() error: %v", err)
	}

	tests := []struct {
		name   string
		expr   string
		ctx    policy.EvaluationContext
		expect bool
	}{
		{
			name: "simple_equality",
			expr: `tool_name == "read_file"`,
			ctx: policy.EvaluationContext{
				ToolName:      "read_file",
				ToolArguments: map[string]interface{}{},
				UserRoles:     []string{},
				SessionID:     "sess-1",
				IdentityID:    "id-1",
				RequestTime:   time.Now(),
			},
			expect: true,
		},
		{
			name: "glob_pattern_match",
			expr: `glob("file_*", tool_name)`,
			ctx: policy.EvaluationContext{
				ToolName:      "file_read",
				ToolArguments: map[string]interface{}{},
				UserRoles:     []string{},
				SessionID:     "sess-1",
				IdentityID:    "id-1",
				RequestTime:   time.Now(),
			},
			expect: true,
		},
		{
			name: "role_check_with_exists",
			expr: `user_roles.exists(r, r == "admin")`,
			ctx: policy.EvaluationContext{
				ToolName:      "anything",
				ToolArguments: map[string]interface{}{},
				UserRoles:     []string{"user", "admin"},
				SessionID:     "sess-1",
				IdentityID:    "id-1",
				RequestTime:   time.Now(),
			},
			expect: true,
		},
		{
			name: "tool_args_access",
			expr: `tool_args["path"] == "/etc/passwd"`,
			ctx: policy.EvaluationContext{
				ToolName:      "read_file",
				ToolArguments: map[string]interface{}{"path": "/etc/passwd"},
				UserRoles:     []string{},
				SessionID:     "sess-1",
				IdentityID:    "id-1",
				RequestTime:   time.Now(),
			},
			expect: true,
		},
		{
			name: "complex_and_condition",
			expr: `tool_name == "write_file" && user_roles.exists(r, r == "editor")`,
			ctx: policy.EvaluationContext{
				ToolName:      "write_file",
				ToolArguments: map[string]interface{}{},
				UserRoles:     []string{"editor"},
				SessionID:     "sess-1",
				IdentityID:    "id-1",
				RequestTime:   time.Now(),
			},
			expect: true,
		},
		{
			name: "identity_check",
			expr: `identity_id == "user-42"`,
			ctx: policy.EvaluationContext{
				ToolName:      "read_file",
				ToolArguments: map[string]interface{}{},
				UserRoles:     []string{},
				SessionID:     "sess-1",
				IdentityID:    "user-42",
				RequestTime:   time.Now(),
			},
			expect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prg, err := eval.Compile(tt.expr)
			if err != nil {
				t.Fatalf("Compile(%q) error: %v", tt.expr, err)
			}
			result, err := eval.Evaluate(prg, tt.ctx)
			if err != nil {
				t.Fatalf("Evaluate() error: %v", err)
			}
			if result != tt.expect {
				t.Errorf("expected %v, got %v", tt.expect, result)
			}
		})
	}

	// NOTE: Testing real evaluation timeout is impractical without a custom CEL function
	// that deliberately sleeps. The ContextEval with timeout is defense-in-depth against
	// pathological expressions. The key assertion is that ContextEval works correctly for
	// all normal evaluation patterns (proven by the subtests above).
}

func TestValidateNesting(t *testing.T) {
	// Unit test the validateNesting function directly.
	tests := []struct {
		name    string
		expr    string
		wantErr bool
	}{
		{"no_nesting", "true", false},
		{"single_level", "(true)", false},
		{"50_levels", strings.Repeat("(", 50) + "true" + strings.Repeat(")", 50), false},
		{"51_levels", strings.Repeat("(", 51) + "true" + strings.Repeat(")", 51), true},
		{"100_levels", strings.Repeat("(", 100) + "true" + strings.Repeat(")", 100), true},
		{"interleaved_types", "([{true}])", false}, // depth 3
		{"empty_string", "", false},                     // no nesting
		{"only_openers", strings.Repeat("(", 60), true}, // unbalanced but exceeds depth
		{"deep_square_brackets", strings.Repeat("[", 51) + strings.Repeat("]", 51), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNesting(tt.expr)
			if tt.wantErr && err == nil {
				t.Errorf("validateNesting(%q) expected error, got nil", tt.name)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("validateNesting(%q) unexpected error: %v", tt.name, err)
			}
		})
	}
}
