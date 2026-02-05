// Package cel provides a CEL-based policy expression evaluator.
package cel

import (
	"fmt"
	"path/filepath"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// Evaluator compiles and evaluates CEL expressions for policy rules.
type Evaluator struct {
	env *cel.Env
}

// NewPolicyEnvironment creates a CEL environment configured for policy evaluation.
// It includes standard extensions and custom functions for tool authorization.
func NewPolicyEnvironment() (*cel.Env, error) {
	return cel.NewEnv(
		// Standard extensions
		ext.Strings(),
		ext.Sets(),

		// Policy variables
		cel.Variable("tool_name", cel.StringType),
		cel.Variable("tool_args", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("user_roles", cel.ListType(cel.StringType)),
		cel.Variable("session_id", cel.StringType),
		cel.Variable("identity_id", cel.StringType),
		cel.Variable("request_time", cel.TimestampType),

		// Custom glob function for tool name pattern matching
		cel.Function("glob",
			cel.Overload("glob_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(pattern, name ref.Val) ref.Val {
					p := pattern.Value().(string)
					n := name.Value().(string)
					matched, _ := filepath.Match(p, n)
					return types.Bool(matched)
				}),
			),
		),
	)
}

// NewEvaluator creates a new CEL evaluator with the policy environment.
func NewEvaluator() (*Evaluator, error) {
	env, err := NewPolicyEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to create policy environment: %w", err)
	}
	return &Evaluator{env: env}, nil
}

// Compile parses and type-checks a CEL expression, returning a compiled program.
func (e *Evaluator) Compile(expression string) (cel.Program, error) {
	ast, issues := e.env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compilation failed: %w", issues.Err())
	}

	prg, err := e.env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, fmt.Errorf("program creation failed: %w", err)
	}

	return prg, nil
}

// Evaluate runs a compiled CEL program against the given context.
// Returns true if the expression evaluates to true, false otherwise.
func (e *Evaluator) Evaluate(prg cel.Program, ctx policy.EvaluationContext) (bool, error) {
	activation := map[string]interface{}{
		"tool_name":    ctx.ToolName,
		"tool_args":    ctx.ToolArguments,
		"user_roles":   ctx.UserRoles,
		"session_id":   ctx.SessionID,
		"identity_id":  ctx.IdentityID,
		"request_time": ctx.RequestTime,
	}

	result, _, err := prg.Eval(activation)
	if err != nil {
		return false, fmt.Errorf("evaluation failed: %w", err)
	}

	boolResult, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression did not return a boolean, got %T", result.Value())
	}

	return boolResult, nil
}
