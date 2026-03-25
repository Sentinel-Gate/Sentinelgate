package sentinelgate

import (
	"errors"
	"fmt"
)

// Sentinel errors for use with errors.Is().
var (
	// ErrPolicyDenied is returned when a policy evaluation results in a deny decision.
	ErrPolicyDenied = errors.New("policy denied")

	// ErrApprovalTimeout is returned when approval polling exceeds the maximum wait time.
	ErrApprovalTimeout = errors.New("approval timeout")

	// ErrServerUnreachable is returned when the SentinelGate server cannot be contacted.
	ErrServerUnreachable = errors.New("server unreachable")
)

// SentinelGateError is the base error type for SDK errors.
type SentinelGateError struct {
	// Code is a machine-readable error code.
	Code string
	// Err is the underlying error.
	Err error
}

// Error returns the error message.
func (e *SentinelGateError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("sentinelgate [%s]: %v", e.Code, e.Err)
	}
	return fmt.Sprintf("sentinelgate [%s]", e.Code)
}

// Unwrap returns the underlying error.
func (e *SentinelGateError) Unwrap() error {
	return e.Err
}

// PolicyDeniedError is returned when a policy evaluation results in a deny decision.
// It contains details about the rule that denied the action.
type PolicyDeniedError struct {
	// RuleID is the identifier of the rule that denied the action.
	RuleID string
	// RuleName is the human-readable name of the denying rule.
	RuleName string
	// Reason explains why the action was denied.
	Reason string
	// HelpURL points to the admin UI for the denying rule.
	HelpURL string
	// HelpText provides human-readable guidance.
	HelpText string
	// RequestID is the unique identifier for this evaluation.
	RequestID string
}

// Error returns a human-readable description of the policy denial.
func (e *PolicyDeniedError) Error() string {
	if e.RuleName != "" {
		return fmt.Sprintf("policy denied by rule '%s': %s", e.RuleName, e.Reason)
	}
	return fmt.Sprintf("policy denied: %s", e.Reason)
}

// Is reports whether this error matches the target error.
// It supports errors.Is(err, ErrPolicyDenied).
func (e *PolicyDeniedError) Is(target error) bool {
	return target == ErrPolicyDenied
}

// ApprovalTimeoutError is returned when approval polling exceeds the maximum wait time.
type ApprovalTimeoutError struct {
	// RequestID is the unique identifier for the evaluation that timed out.
	RequestID string
}

// Error returns a human-readable description of the approval timeout.
func (e *ApprovalTimeoutError) Error() string {
	return fmt.Sprintf("approval timeout for request %s", e.RequestID)
}

// Is reports whether this error matches the target error.
// It supports errors.Is(err, ErrApprovalTimeout).
func (e *ApprovalTimeoutError) Is(target error) bool {
	return target == ErrApprovalTimeout
}

// ServerUnreachableError is returned when the SentinelGate server cannot be contacted.
type ServerUnreachableError struct {
	// Cause is the underlying error that caused the server to be unreachable.
	Cause error
}

// Error returns a human-readable description of the server unreachable error.
func (e *ServerUnreachableError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("server unreachable: %v", e.Cause)
	}
	return "server unreachable"
}

// Unwrap returns the underlying error cause.
func (e *ServerUnreachableError) Unwrap() error {
	return e.Cause
}

// Is reports whether this error matches the target error.
// It supports errors.Is(err, ErrServerUnreachable).
func (e *ServerUnreachableError) Is(target error) bool {
	return target == ErrServerUnreachable
}
