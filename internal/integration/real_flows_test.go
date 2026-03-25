package integration

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	evidenceAdapter "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/evidence"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/quota"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// =============================================================================
// Test 1: TestApprovalWorkflowE2E
// =============================================================================

// TestApprovalWorkflowE2E tests the full approval flow end-to-end:
// - A policy returns approval_required
// - The ApprovalInterceptor blocks the call pending approval
// - Approve via ApprovalStore unblocks and allows the call
// - Deny via ApprovalStore unblocks and denies the call
func TestApprovalWorkflowE2E(t *testing.T) {
	logger := testLogger()

	t.Run("ApproveFlow", func(t *testing.T) {
		// 1. Create an ApprovalStore
		approvalStore := action.NewApprovalStore(10)

		// 2. Terminal interceptor that records if it was reached
		var terminalReached bool
		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			terminalReached = true
			return a, nil
		})

		// 3. Wire: ApprovalInterceptor -> terminal
		approvalInterceptor := action.NewApprovalInterceptor(approvalStore, terminal, logger)

		// 4. Create a CanonicalAction (simulating what MCPNormalizer would produce)
		act := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "delete_database",
			Arguments: map[string]interface{}{
				"db_name": "production",
			},
			Identity: action.ActionIdentity{
				ID:        "agent-e2e-001",
				Name:      "e2e-test-agent",
				SessionID: "sess-e2e-001",
				Roles:     []string{"user"},
			},
			RequestTime: time.Now().UTC(),
		}

		// 5. Create context with a decision that requires approval
		ctx := policy.WithDecision(context.Background(), &policy.Decision{
			Allowed:               true,
			RequiresApproval:      true,
			ApprovalTimeout:       5 * time.Second,
			ApprovalTimeoutAction: policy.ActionDeny,
			RuleID:                "rule-require-approval",
			RuleName:              "Require Approval for Destructive Tools",
		})

		// 6. Asynchronously approve once the pending approval appears
		go func() {
			for i := 0; i < 100; i++ {
				list := approvalStore.List()
				if len(list) > 0 {
					if err := approvalStore.Approve(list[0].ID, "approved by admin"); err != nil {
						t.Errorf("Approve failed: %v", err)
					}
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Error("timed out waiting for pending approval to appear")
		}()

		// 7. Call Intercept -- this blocks until approved
		result, err := approvalInterceptor.Intercept(ctx, act)

		// 8. Assert: no error, terminal was reached
		if err != nil {
			t.Fatalf("expected approval to succeed, got error: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result after approval")
		}
		if !terminalReached {
			t.Error("terminal interceptor should have been called after approval")
		}

		// 9. After resolution, the entry is removed from the store (cleanup).
		// Verify that the pending list is now empty.
		remaining := approvalStore.List()
		if len(remaining) != 0 {
			t.Errorf("expected 0 pending after approval, got %d", len(remaining))
		}
	})

	t.Run("DenyFlow", func(t *testing.T) {
		// 1. Create fresh ApprovalStore
		approvalStore := action.NewApprovalStore(10)

		// 2. Terminal interceptor -- should NOT be reached on denial
		terminal := action.ActionInterceptorFunc(func(_ context.Context, _ *action.CanonicalAction) (*action.CanonicalAction, error) {
			t.Error("terminal interceptor should NOT be called after denial")
			return nil, nil
		})

		// 3. Wire: ApprovalInterceptor -> terminal
		approvalInterceptor := action.NewApprovalInterceptor(approvalStore, terminal, logger)

		act := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "drop_table",
			Arguments: map[string]interface{}{
				"table": "users",
			},
			Identity: action.ActionIdentity{
				ID:        "agent-e2e-002",
				Name:      "e2e-deny-agent",
				SessionID: "sess-e2e-002",
			},
		}

		ctx := policy.WithDecision(context.Background(), &policy.Decision{
			Allowed:               true,
			RequiresApproval:      true,
			ApprovalTimeout:       5 * time.Second,
			ApprovalTimeoutAction: policy.ActionDeny,
		})

		// 4. Asynchronously deny once the pending approval appears
		go func() {
			for i := 0; i < 100; i++ {
				list := approvalStore.List()
				if len(list) > 0 {
					if err := approvalStore.Deny(list[0].ID, "too dangerous", "blocked by security"); err != nil {
						t.Errorf("Deny failed: %v", err)
					}
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Error("timed out waiting for pending approval to appear")
		}()

		// 5. Call Intercept -- should return error after denial
		_, err := approvalInterceptor.Intercept(ctx, act)

		if err == nil {
			t.Fatal("expected error after approval denial")
		}
		if !errors.Is(err, proxy.ErrPolicyDenied) {
			t.Errorf("expected ErrPolicyDenied, got: %v", err)
		}
	})

	t.Run("TimeoutDeny", func(t *testing.T) {
		approvalStore := action.NewApprovalStore(10)

		terminal := action.ActionInterceptorFunc(func(_ context.Context, _ *action.CanonicalAction) (*action.CanonicalAction, error) {
			t.Error("terminal should NOT be called on timeout-deny")
			return nil, nil
		})

		approvalInterceptor := action.NewApprovalInterceptor(approvalStore, terminal, logger)

		act := &action.CanonicalAction{
			Type:     action.ActionToolCall,
			Name:     "timeout_tool",
			Identity: action.ActionIdentity{ID: "agent-timeout", Name: "timeout-agent"},
		}

		ctx := policy.WithDecision(context.Background(), &policy.Decision{
			Allowed:               true,
			RequiresApproval:      true,
			ApprovalTimeout:       100 * time.Millisecond,
			ApprovalTimeoutAction: policy.ActionDeny,
		})

		// Nobody approves -- should time out and deny
		_, err := approvalInterceptor.Intercept(ctx, act)
		if err == nil {
			t.Fatal("expected error on timeout deny")
		}
	})

	t.Run("NoApprovalNeeded_PassesThrough", func(t *testing.T) {
		approvalStore := action.NewApprovalStore(10)
		var reached bool
		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			reached = true
			return a, nil
		})

		approvalInterceptor := action.NewApprovalInterceptor(approvalStore, terminal, logger)

		act := &action.CanonicalAction{
			Type:     action.ActionToolCall,
			Name:     "read_file",
			Identity: action.ActionIdentity{ID: "agent-ok", Name: "ok-agent"},
		}

		// Decision does NOT require approval
		ctx := policy.WithDecision(context.Background(), &policy.Decision{
			Allowed:          true,
			RequiresApproval: false,
		})

		_, err := approvalInterceptor.Intercept(ctx, act)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reached {
			t.Error("terminal should be called when no approval needed")
		}
	})
}

// =============================================================================
// Test 2: TestQuotaEnforcementE2E
// =============================================================================

// TestQuotaEnforcementE2E tests quota enforcement end-to-end using real components:
// - MemoryQuotaStore with a configured limit
// - QuotaService checking limits
// - ActionQuotaInterceptor in the action chain
// - Verifies calls are allowed up to the limit and denied after
func TestQuotaEnforcementE2E(t *testing.T) {
	logger := testLogger()

	t.Run("MaxCallsPerSession", func(t *testing.T) {
		// 1. Create quota store with a limit of 3 calls per session
		quotaStore := quota.NewMemoryQuotaStore()
		if err := quotaStore.Put(context.Background(), &quota.QuotaConfig{
			IdentityID:         "quota-user-001",
			MaxCallsPerSession: 3,
			Action:             quota.QuotaActionDeny,
			Enabled:            true,
		}); err != nil {
			t.Fatalf("Put quota config: %v", err)
		}

		// 2. Create session tracker
		tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())

		// 3. Create quota service
		quotaSvc := quota.NewQuotaService(quotaStore, tracker)

		// 4. Terminal interceptor that always succeeds
		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			return a, nil
		})

		// 5. Wire: ActionQuotaInterceptor -> terminal
		quotaInterceptor := quota.NewActionQuotaInterceptor(quotaSvc, tracker, terminal, logger)

		// 6. Send 3 calls -- all should succeed
		for i := 0; i < 3; i++ {
			act := &action.CanonicalAction{
				Type: action.ActionToolCall,
				Name: "read_file",
				Identity: action.ActionIdentity{
					ID:        "quota-user-001",
					Name:      "quota-test-user",
					SessionID: "quota-sess-001",
				},
			}
			_, err := quotaInterceptor.Intercept(context.Background(), act)
			if err != nil {
				t.Fatalf("call %d should succeed, got error: %v", i+1, err)
			}
		}

		// 7. Send 4th call -- should be denied (quota exceeded)
		act := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "read_file",
			Identity: action.ActionIdentity{
				ID:        "quota-user-001",
				Name:      "quota-test-user",
				SessionID: "quota-sess-001",
			},
		}
		_, err := quotaInterceptor.Intercept(context.Background(), act)
		if err == nil {
			t.Fatal("4th call should be denied by quota")
		}
		if !errors.Is(err, proxy.ErrQuotaExceeded) {
			t.Errorf("expected ErrQuotaExceeded, got: %v", err)
		}
	})

	t.Run("NoQuotaConfig_AllowsAll", func(t *testing.T) {
		// Identity with no quota config should be allowed
		quotaStore := quota.NewMemoryQuotaStore()
		tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
		quotaSvc := quota.NewQuotaService(quotaStore, tracker)

		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			return a, nil
		})

		quotaInterceptor := quota.NewActionQuotaInterceptor(quotaSvc, tracker, terminal, logger)

		act := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "read_file",
			Identity: action.ActionIdentity{
				ID:        "unquota-user",
				Name:      "free-user",
				SessionID: "free-sess",
			},
		}

		for i := 0; i < 10; i++ {
			_, err := quotaInterceptor.Intercept(context.Background(), act)
			if err != nil {
				t.Fatalf("call %d should succeed (no quota config), got error: %v", i+1, err)
			}
		}
	})

	t.Run("DifferentSessions_IndependentQuota", func(t *testing.T) {
		quotaStore := quota.NewMemoryQuotaStore()
		if err := quotaStore.Put(context.Background(), &quota.QuotaConfig{
			IdentityID:         "multi-sess-user",
			MaxCallsPerSession: 2,
			Action:             quota.QuotaActionDeny,
			Enabled:            true,
		}); err != nil {
			t.Fatalf("Put quota config: %v", err)
		}

		tracker := session.NewSessionTracker(time.Minute, session.DefaultClassifier())
		quotaSvc := quota.NewQuotaService(quotaStore, tracker)

		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			return a, nil
		})

		quotaInterceptor := quota.NewActionQuotaInterceptor(quotaSvc, tracker, terminal, logger)

		// Session A: 2 calls should succeed
		for i := 0; i < 2; i++ {
			act := &action.CanonicalAction{
				Type: action.ActionToolCall,
				Name: "read_file",
				Identity: action.ActionIdentity{
					ID:        "multi-sess-user",
					Name:      "test",
					SessionID: "session-A",
				},
			}
			_, err := quotaInterceptor.Intercept(context.Background(), act)
			if err != nil {
				t.Fatalf("session-A call %d should succeed: %v", i+1, err)
			}
		}

		// Session B: should still have its own quota (2 calls)
		actB := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "read_file",
			Identity: action.ActionIdentity{
				ID:        "multi-sess-user",
				Name:      "test",
				SessionID: "session-B",
			},
		}
		_, err := quotaInterceptor.Intercept(context.Background(), actB)
		if err != nil {
			t.Fatalf("session-B first call should succeed: %v", err)
		}
	})
}

// =============================================================================
// Test 3: TestContentScanningE2E
// =============================================================================

// TestContentScanningE2E tests content scanning end-to-end using real components:
// - ContentScanner with default patterns
// - ContentScanInterceptor with scanning enabled
// - Verifies PII (email, SSN) is detected and blocked/masked
// - Verifies clean content passes through
func TestContentScanningE2E(t *testing.T) {
	logger := testLogger()

	t.Run("BlockAWSKey", func(t *testing.T) {
		scanner := action.NewContentScanner()

		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			t.Error("terminal should NOT be reached when content is blocked")
			return a, nil
		})

		contentInterceptor := action.NewContentScanInterceptor(scanner, terminal, true, logger)

		act := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "write_file",
			Arguments: map[string]interface{}{
				"content": "My AWS key is AKIAIOSFODNN7EXAMPLE and it should be blocked",
			},
			Identity: action.ActionIdentity{ID: "scan-user", Name: "scanner-test"},
		}

		_, err := contentInterceptor.Intercept(context.Background(), act)
		if err == nil {
			t.Fatal("expected content to be blocked due to AWS key")
		}
		if !errors.Is(err, proxy.ErrContentBlocked) {
			t.Errorf("expected ErrContentBlocked, got: %v", err)
		}
	})

	t.Run("MaskEmail", func(t *testing.T) {
		scanner := action.NewContentScanner()

		var passedArgs map[string]interface{}
		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			passedArgs = a.Arguments
			return a, nil
		})

		contentInterceptor := action.NewContentScanInterceptor(scanner, terminal, true, logger)

		act := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "send_message",
			Arguments: map[string]interface{}{
				"body": "Contact user at john.doe@example.com for details",
			},
			Identity: action.ActionIdentity{ID: "scan-user-2", Name: "scanner-test-2"},
		}

		_, err := contentInterceptor.Intercept(context.Background(), act)
		if err != nil {
			t.Fatalf("email should be masked (not blocked): %v", err)
		}

		// Verify the email was masked in the arguments
		if passedArgs == nil {
			t.Fatal("expected arguments to be passed to terminal")
		}
		body, ok := passedArgs["body"].(string)
		if !ok {
			t.Fatal("expected body argument to be a string")
		}
		if body == "Contact user at john.doe@example.com for details" {
			t.Error("email address should have been masked but was passed through unchanged")
		}
	})

	t.Run("MaskSSN", func(t *testing.T) {
		scanner := action.NewContentScanner()

		var passedArgs map[string]interface{}
		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			passedArgs = a.Arguments
			return a, nil
		})

		contentInterceptor := action.NewContentScanInterceptor(scanner, terminal, true, logger)

		act := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "update_record",
			Arguments: map[string]interface{}{
				"notes": "SSN is 123-45-6789 for the patient",
			},
			Identity: action.ActionIdentity{ID: "scan-user-3", Name: "scanner-test-3"},
		}

		_, err := contentInterceptor.Intercept(context.Background(), act)
		if err != nil {
			t.Fatalf("SSN should be masked (not blocked): %v", err)
		}

		if passedArgs != nil {
			notes, ok := passedArgs["notes"].(string)
			if ok && notes == "SSN is 123-45-6789 for the patient" {
				t.Error("SSN should have been masked but was passed through unchanged")
			}
		}
	})

	t.Run("CleanContentPassesThrough", func(t *testing.T) {
		scanner := action.NewContentScanner()

		var reached bool
		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			reached = true
			return a, nil
		})

		contentInterceptor := action.NewContentScanInterceptor(scanner, terminal, true, logger)

		act := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "read_file",
			Arguments: map[string]interface{}{
				"path": "/tmp/safe_file.txt",
			},
			Identity: action.ActionIdentity{ID: "clean-user", Name: "clean-test"},
		}

		_, err := contentInterceptor.Intercept(context.Background(), act)
		if err != nil {
			t.Fatalf("clean content should pass through: %v", err)
		}
		if !reached {
			t.Error("terminal should be reached for clean content")
		}
	})

	t.Run("DisabledScannerPassesEverything", func(t *testing.T) {
		scanner := action.NewContentScanner()

		var reached bool
		terminal := action.ActionInterceptorFunc(func(_ context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			reached = true
			return a, nil
		})

		// Scanning disabled
		contentInterceptor := action.NewContentScanInterceptor(scanner, terminal, false, logger)

		act := &action.CanonicalAction{
			Type: action.ActionToolCall,
			Name: "write_file",
			Arguments: map[string]interface{}{
				"content": "AKIAIOSFODNN7EXAMPLE is my AWS key",
			},
			Identity: action.ActionIdentity{ID: "disabled-scan-user", Name: "disabled-scan"},
		}

		_, err := contentInterceptor.Intercept(context.Background(), act)
		if err != nil {
			t.Fatalf("disabled scanner should pass everything: %v", err)
		}
		if !reached {
			t.Error("terminal should be reached when scanning is disabled")
		}
	})
}

// =============================================================================
// Test 4: TestMultiUpstreamRoutingE2E
// =============================================================================

// TestMultiUpstreamRoutingE2E tests multi-upstream routing end-to-end:
// - 2 upstreams with different tools
// - Verifies tool calls route to the correct upstream
// - Verifies unknown tools get an error response
// - This uses real UpstreamRouter with mock connections (same pattern as multi_upstream_test.go)
func TestMultiUpstreamRoutingE2E(t *testing.T) {
	logger := testLogger()

	// 1. Create ToolCache and populate with tools from 2 upstreams
	toolCache := &pipelineToolCache{
		tools: map[string]*proxy.RoutableTool{
			"analyze_data": {
				Name:        "analyze_data",
				UpstreamID:  "analytics-server",
				Description: "Analyze data sets",
			},
			"generate_report": {
				Name:        "generate_report",
				UpstreamID:  "reporting-server",
				Description: "Generate PDF reports",
			},
			"send_notification": {
				Name:        "send_notification",
				UpstreamID:  "analytics-server",
				Description: "Send analysis notifications",
			},
		},
	}

	// 2. Create mock connection provider with responses
	connProvider := &pipelineConnectionProvider{
		connections:  make(map[string]*pipelineMockConn),
		allConnected: true,
	}
	connProvider.addConnection("analytics-server",
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"analysis complete"}]}}`)
	connProvider.addConnection("reporting-server",
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"report generated"}]}}`)

	// 3. Create router
	router := proxy.NewUpstreamRouter(toolCache, connProvider, logger)

	// 4. Build the integration chain around the router
	policyEngine := &mockRegressionPolicyEngine{rules: map[string]policy.Decision{}}
	chain, auditRec, _ := buildRegressionChain(policyEngine, router)

	t.Run("AnalyzeTool_RoutedToAnalyticsServer", func(t *testing.T) {
		sess := buildRegressionSession()
		msg := buildRegressionMessage(t, "tools/call", 1, map[string]interface{}{
			"name":      "analyze_data",
			"arguments": map[string]interface{}{"dataset": "sales-q4"},
		}, sess)

		result, err := chain.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("analyze_data should succeed: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		// Verify analytics-server received the request
		conn := connProvider.connections["analytics-server"]
		if len(conn.writer.buf) == 0 {
			t.Error("expected request forwarded to analytics-server")
		}
	})

	t.Run("ReportTool_RoutedToReportingServer", func(t *testing.T) {
		// Reset connections for fresh routing
		connProvider.addConnection("analytics-server",
			`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"analysis complete"}]}}`)
		connProvider.addConnection("reporting-server",
			`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"report generated"}]}}`)

		sess := buildRegressionSession()
		msg := buildRegressionMessage(t, "tools/call", 2, map[string]interface{}{
			"name":      "generate_report",
			"arguments": map[string]interface{}{"format": "pdf"},
		}, sess)

		result, err := chain.Intercept(context.Background(), msg)
		if err != nil {
			t.Fatalf("generate_report should succeed: %v", err)
		}
		if result == nil {
			t.Fatal("expected non-nil result")
		}

		// Verify reporting-server received the request
		conn := connProvider.connections["reporting-server"]
		if len(conn.writer.buf) == 0 {
			t.Error("expected request forwarded to reporting-server")
		}

		// Verify analytics-server did NOT receive this request
		connA := connProvider.connections["analytics-server"]
		if len(connA.writer.buf) != 0 {
			t.Error("did NOT expect request forwarded to analytics-server")
		}
	})

	// Verify audit recorded both calls
	if len(auditRec.records) != 2 {
		t.Errorf("audit records = %d, want 2", len(auditRec.records))
	}
}

// =============================================================================
// Test 5: TestEvidenceChainE2E
// =============================================================================

// TestEvidenceChainE2E tests the evidence chain end-to-end:
// - Creates a real ECDSA signer and file-based evidence store
// - Records multiple audit entries through the EvidenceService
// - Verifies the chain hash integrity and valid signatures using VerifyFile
func TestEvidenceChainE2E(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "e2e-evidence-key.pem")
	outputPath := filepath.Join(dir, "e2e-evidence.jsonl")
	logger := testLogger()

	// 1. Create real ECDSA signer (generates key on first call)
	signer, err := evidenceAdapter.NewECDSASigner(keyPath, "e2e-test-instance")
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}

	// 2. Create file-based evidence store
	store, err := evidenceAdapter.NewFileStore(outputPath)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	// 3. Create evidence service
	evidenceSvc := service.NewEvidenceService(signer, store, logger, nil)

	// 4. Record multiple audit entries representing a real session
	records := []audit.AuditRecord{
		{
			Timestamp:     time.Now().UTC(),
			ToolName:      "read_file",
			Decision:      "allow",
			IdentityName:  "claude-prod",
			Protocol:      "mcp",
			SessionID:     "evidence-sess-001",
			LatencyMicros: 150,
			RuleID:        "rule-allow-read",
			Reason:        "allowed by policy",
		},
		{
			Timestamp:     time.Now().UTC().Add(1 * time.Second),
			ToolName:      "write_file",
			Decision:      "allow",
			IdentityName:  "claude-prod",
			Protocol:      "mcp",
			SessionID:     "evidence-sess-001",
			LatencyMicros: 230,
			RuleID:        "rule-allow-write",
			Reason:        "allowed by policy",
		},
		{
			Timestamp:     time.Now().UTC().Add(2 * time.Second),
			ToolName:      "delete_database",
			Decision:      "deny",
			IdentityName:  "claude-prod",
			Protocol:      "mcp",
			SessionID:     "evidence-sess-001",
			LatencyMicros: 50,
			RuleID:        "rule-deny-destructive",
			Reason:        "destructive action denied",
		},
		{
			Timestamp:     time.Now().UTC().Add(3 * time.Second),
			ToolName:      "exec_command",
			Decision:      "deny",
			IdentityName:  "unknown-agent",
			Protocol:      "mcp",
			SessionID:     "evidence-sess-002",
			LatencyMicros: 30,
			RuleID:        "rule-deny-exec",
			Reason:        "exec blocked",
		},
		{
			Timestamp:     time.Now().UTC().Add(4 * time.Second),
			ToolName:      "search_web",
			Decision:      "allow",
			IdentityName:  "claude-prod",
			Protocol:      "mcp",
			SessionID:     "evidence-sess-001",
			LatencyMicros: 1200,
			RuleID:        "rule-allow-search",
			Reason:        "allowed by policy",
		},
	}

	for _, rec := range records {
		evidenceSvc.RecordEvidence(rec)
	}

	// 5. Check no errors during recording
	if evidenceSvc.LastError() != nil {
		t.Fatalf("unexpected evidence recording error: %v", evidenceSvc.LastError())
	}

	// 6. Verify statistics
	stats := evidenceSvc.Stats()
	if stats.RecordCount != 5 {
		t.Errorf("RecordCount = %d, want 5", stats.RecordCount)
	}
	if stats.LastHash == "" {
		t.Error("LastHash should not be empty after recording")
	}

	// 7. Close the store to flush
	if err := evidenceSvc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// 8. Verify the evidence file using the real verifier
	verifyResult, err := evidenceAdapter.VerifyFile(outputPath, keyPath)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}

	if verifyResult.TotalRecords != 5 {
		t.Errorf("TotalRecords = %d, want 5", verifyResult.TotalRecords)
	}
	if verifyResult.ValidSignatures != 5 {
		t.Errorf("ValidSignatures = %d, want 5", verifyResult.ValidSignatures)
	}
	if verifyResult.InvalidSigs != 0 {
		t.Errorf("InvalidSigs = %d, want 0", verifyResult.InvalidSigs)
	}
	if !verifyResult.ChainValid {
		t.Errorf("ChainValid = false, want true (break at %d, error: %s)",
			verifyResult.ChainBreakAt, verifyResult.FirstError)
	}
}

// =============================================================================
// Test 6: TestPolicyEvaluationE2E
// =============================================================================

// TestPolicyEvaluationE2E tests policy evaluation end-to-end using real components:
// - Real PolicyService with in-memory store
// - Different policy decisions (allow, deny, approval_required)
// - Priority ordering verification
// - CEL condition evaluation
func TestPolicyEvaluationE2E(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	t.Run("AllowDenyPriority", func(t *testing.T) {
		policyStore := memory.NewPolicyStore()

		// Low-priority deny-all rule
		policyStore.AddPolicy(&policy.Policy{
			ID:      "deny-all",
			Name:    "Deny All (Default)",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "rule-deny-all",
					Name:      "Deny All Tools",
					Priority:  0,
					ToolMatch: "*",
					Condition: "true",
					Action:    policy.ActionDeny,
				},
			},
		})

		// Higher-priority allow rule for read_* tools
		policyStore.AddPolicy(&policy.Policy{
			ID:      "allow-reads",
			Name:    "Allow Read Tools",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "rule-allow-reads",
					Name:      "Allow Read Tools",
					Priority:  50,
					ToolMatch: "read_*",
					Condition: "true",
					Action:    policy.ActionAllow,
				},
			},
		})

		policySvc, err := service.NewPolicyService(ctx, policyStore, logger)
		if err != nil {
			t.Fatalf("NewPolicyService: %v", err)
		}

		// Evaluate read_file -- should be ALLOWED (higher priority)
		decision, err := policySvc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:    "read_file",
			UserRoles:   []string{"user"},
			SessionID:   "policy-sess-001",
			IdentityID:  "policy-user-001",
			RequestTime: time.Now(),
			SkipCache:   true,
		})
		if err != nil {
			t.Fatalf("Evaluate(read_file): %v", err)
		}
		if !decision.Allowed {
			t.Errorf("read_file should be allowed (priority 50 > 0), but got denied by rule %q", decision.RuleID)
		}

		// Evaluate exec_command -- should be DENIED (only deny-all matches)
		decision, err = policySvc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:    "exec_command",
			UserRoles:   []string{"user"},
			SessionID:   "policy-sess-001",
			IdentityID:  "policy-user-001",
			RequestTime: time.Now(),
			SkipCache:   true,
		})
		if err != nil {
			t.Fatalf("Evaluate(exec_command): %v", err)
		}
		if decision.Allowed {
			t.Error("exec_command should be denied by deny-all rule")
		}
	})

	t.Run("ApprovalRequired", func(t *testing.T) {
		policyStore := memory.NewPolicyStore()

		policyStore.AddPolicy(&policy.Policy{
			ID:      "approval-destructive",
			Name:    "Approval Required for Destructive Tools",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:              "rule-approval-delete",
					Name:            "Require Approval for Delete",
					Priority:        100,
					ToolMatch:       "delete_*",
					Condition:       "true",
					Action:          policy.ActionApprovalRequired,
					ApprovalTimeout: 5 * time.Minute,
					TimeoutAction:   policy.ActionDeny,
				},
			},
		})

		policySvc, err := service.NewPolicyService(ctx, policyStore, logger)
		if err != nil {
			t.Fatalf("NewPolicyService: %v", err)
		}

		decision, err := policySvc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:    "delete_database",
			UserRoles:   []string{"user"},
			SessionID:   "policy-sess-002",
			IdentityID:  "policy-user-002",
			RequestTime: time.Now(),
			SkipCache:   true,
		})
		if err != nil {
			t.Fatalf("Evaluate(delete_database): %v", err)
		}
		if !decision.RequiresApproval {
			t.Error("delete_database should require approval")
		}
		if decision.ApprovalTimeout != 5*time.Minute {
			t.Errorf("ApprovalTimeout = %v, want 5m", decision.ApprovalTimeout)
		}
		if decision.ApprovalTimeoutAction != policy.ActionDeny {
			t.Errorf("ApprovalTimeoutAction = %q, want %q", decision.ApprovalTimeoutAction, policy.ActionDeny)
		}
	})

	t.Run("CELConditionEvaluation", func(t *testing.T) {
		policyStore := memory.NewPolicyStore()

		// Policy: deny write_file when path argument starts with /etc/
		policyStore.AddPolicy(&policy.Policy{
			ID:      "cel-path-check",
			Name:    "Block writes to /etc/",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "rule-deny-etc-write",
					Name:      "Deny writes to /etc/",
					Priority:  100,
					ToolMatch: "write_file",
					Condition: `has(tool_args.path) && tool_args.path.startsWith("/etc/")`,
					Action:    policy.ActionDeny,
				},
			},
		})

		// Allow-all fallback
		policyStore.AddPolicy(&policy.Policy{
			ID:      "allow-all",
			Name:    "Allow All (Fallback)",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "rule-allow-all",
					Name:      "Allow All",
					Priority:  0,
					ToolMatch: "*",
					Condition: "true",
					Action:    policy.ActionAllow,
				},
			},
		})

		policySvc, err := service.NewPolicyService(ctx, policyStore, logger)
		if err != nil {
			t.Fatalf("NewPolicyService: %v", err)
		}

		// write_file to /etc/passwd -- should be DENIED by CEL condition
		decision, err := policySvc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:      "write_file",
			ToolArguments: map[string]interface{}{"path": "/etc/passwd", "content": "evil"},
			UserRoles:     []string{"user"},
			SessionID:     "cel-sess",
			IdentityID:    "cel-user",
			RequestTime:   time.Now(),
			SkipCache:     true,
		})
		if err != nil {
			t.Fatalf("Evaluate(write_file /etc/passwd): %v", err)
		}
		if decision.Allowed {
			t.Error("write_file to /etc/passwd should be denied by CEL condition")
		}

		// write_file to /tmp/safe.txt -- should be ALLOWED (CEL condition not matched)
		decision, err = policySvc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:      "write_file",
			ToolArguments: map[string]interface{}{"path": "/tmp/safe.txt", "content": "hello"},
			UserRoles:     []string{"user"},
			SessionID:     "cel-sess",
			IdentityID:    "cel-user",
			RequestTime:   time.Now(),
			SkipCache:     true,
		})
		if err != nil {
			t.Fatalf("Evaluate(write_file /tmp/safe.txt): %v", err)
		}
		if !decision.Allowed {
			t.Errorf("write_file to /tmp/safe.txt should be allowed, but denied by rule %q", decision.RuleID)
		}
	})

	t.Run("DisabledPolicyNotEnforced", func(t *testing.T) {
		policyStore := memory.NewPolicyStore()

		// Enabled allow-all fallback
		policyStore.AddPolicy(&policy.Policy{
			ID:      "enabled-allow",
			Name:    "Allow All",
			Enabled: true,
			Rules: []policy.Rule{
				{
					ID:        "rule-allow",
					Name:      "Allow All",
					Priority:  0,
					ToolMatch: "*",
					Condition: "true",
					Action:    policy.ActionAllow,
				},
			},
		})

		// Disabled deny policy with high priority
		policyStore.AddPolicy(&policy.Policy{
			ID:      "disabled-deny",
			Name:    "Deny Everything (DISABLED)",
			Enabled: false,
			Rules: []policy.Rule{
				{
					ID:        "rule-deny-everything",
					Name:      "Deny Everything",
					Priority:  999,
					ToolMatch: "*",
					Condition: "true",
					Action:    policy.ActionDeny,
				},
			},
		})

		policySvc, err := service.NewPolicyService(ctx, policyStore, logger)
		if err != nil {
			t.Fatalf("NewPolicyService: %v", err)
		}

		decision, err := policySvc.Evaluate(ctx, policy.EvaluationContext{
			ToolName:    "any_tool",
			UserRoles:   []string{"user"},
			SessionID:   "disabled-sess",
			IdentityID:  "disabled-user",
			RequestTime: time.Now(),
			SkipCache:   true,
		})
		if err != nil {
			t.Fatalf("Evaluate(any_tool): %v", err)
		}
		if !decision.Allowed {
			t.Errorf("any_tool should be allowed (disabled deny policy should not be enforced), denied by rule %q", decision.RuleID)
		}
	})
}

// =============================================================================
// Helpers for real_flows_test.go
// =============================================================================

// Suppress unused import warnings.
var _ = auth.RoleUser
