// Package cel provides a CEL-based policy expression evaluator.
package cel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// maxExpressionLength is the maximum allowed length for CEL expressions (SECU-05).
const maxExpressionLength = 1024

// maxCostBudget is the CEL runtime cost limit to prevent cost-exhaustion DoS (HARDEN-02).
const maxCostBudget = 100_000

// maxNestingDepth is the maximum allowed parenthesis/bracket nesting depth (HARDEN-02).
const maxNestingDepth = 50

// evalTimeout is the maximum time allowed for a single CEL evaluation (HARDEN-02).
const evalTimeout = 5 * time.Second

// interruptCheckFreq is how often (in comprehension iterations) context cancellation is checked.
const interruptCheckFreq = 100

// Evaluator compiles and evaluates CEL expressions for policy rules.
type Evaluator struct {
	env *cel.Env
}

// NewPolicyEnvironment creates a CEL environment configured for policy evaluation.
// It delegates to NewUniversalPolicyEnvironment() which includes all universal variables
// and custom functions, maintaining backward compatibility with existing callers.
func NewPolicyEnvironment() (*cel.Env, error) {
	return NewUniversalPolicyEnvironment()
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

	prg, err := e.env.Program(ast,
		cel.EvalOptions(cel.OptOptimize),
		cel.CostLimit(maxCostBudget),
		cel.InterruptCheckFrequency(interruptCheckFreq),
	)
	if err != nil {
		return nil, fmt.Errorf("program creation failed: %w", err)
	}

	return prg, nil
}

// validateNesting checks that the expression does not exceed the maximum allowed
// nesting depth for parentheses, brackets, and braces (HARDEN-02).
func validateNesting(expr string) error {
	var depth, maxDepth int
	for _, ch := range expr {
		switch ch {
		case '(', '[', '{':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
		case ')', ']', '}':
			depth--
		}
	}
	if maxDepth > maxNestingDepth {
		return fmt.Errorf("expression nesting too deep: %d levels (max %d)", maxDepth, maxNestingDepth)
	}
	return nil
}

// ValidateExpression checks that a CEL expression is syntactically valid and safe for
// policy evaluation (SECU-05, HARDEN-02). It performs compile-time validation and enforces
// safety limits (expression length, nesting depth).
func (e *Evaluator) ValidateExpression(expr string) error {
	if len(expr) > maxExpressionLength {
		return fmt.Errorf("expression too long: %d characters (max %d)", len(expr), maxExpressionLength)
	}

	if expr == "" {
		return errors.New("expression is empty")
	}

	if err := validateNesting(expr); err != nil {
		return err
	}

	_, err := e.Compile(expr)
	if err != nil {
		return fmt.Errorf("invalid CEL expression: %w", err)
	}

	return nil
}

// Evaluate runs a compiled CEL program against the given evaluation context.
// Returns true if the expression evaluates to true, false otherwise.
// Uses BuildUniversalActivation to populate all variables (backward-compatible,
// universal, and destination) and ContextEval with a timeout to prevent
// indefinite evaluation hangs (HARDEN-02).
func (e *Evaluator) Evaluate(prg cel.Program, evalCtx policy.EvaluationContext) (bool, error) {
	activation := BuildUniversalActivation(evalCtx)

	ctx, cancel := context.WithTimeout(context.Background(), evalTimeout)
	defer cancel()

	result, _, err := prg.ContextEval(ctx, activation)
	if err != nil {
		return false, fmt.Errorf("evaluation failed: %w", err)
	}

	boolResult, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("expression did not return a boolean, got %T", result.Value())
	}

	return boolResult, nil
}
