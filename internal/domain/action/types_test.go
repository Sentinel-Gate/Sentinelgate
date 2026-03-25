package action

import (
	"testing"
)

func TestActionType_String(t *testing.T) {
	tests := []struct {
		actionType ActionType
		expected   string
	}{
		{ActionToolCall, "tool_call"},
		{ActionHTTPRequest, "http_request"},
		{ActionWebSocketMessage, "websocket_message"},
		{ActionCommandExec, "command_exec"},
		{ActionFileAccess, "file_access"},
		{ActionNetworkConnect, "network_connect"},
		{ActionSampling, "sampling"},
		{ActionElicitation, "elicitation"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.actionType.String(); got != tt.expected {
				t.Errorf("ActionType.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestDecision_String(t *testing.T) {
	tests := []struct {
		decision Decision
		expected string
	}{
		{DecisionAllow, "allow"},
		{DecisionDeny, "deny"},
		{DecisionApprovalRequired, "approval_required"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.decision.String(); got != tt.expected {
				t.Errorf("Decision.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestInterceptResult_IsAllowed(t *testing.T) {
	tests := []struct {
		name     string
		decision Decision
		expected bool
	}{
		{"allow is allowed", DecisionAllow, true},
		{"deny is not allowed", DecisionDeny, false},
		{"approval_required is not allowed", DecisionApprovalRequired, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &InterceptResult{Decision: tt.decision}
			if got := result.IsAllowed(); got != tt.expected {
				t.Errorf("InterceptResult.IsAllowed() = %v, want %v", got, tt.expected)
			}
		})
	}
}
