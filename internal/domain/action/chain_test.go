package action

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestInterceptorChain_FullFlow(t *testing.T) {
	normalizer := NewMCPNormalizer()
	logger := testLogger()

	// Mock ActionInterceptor that passes through
	passthrough := ActionInterceptorFunc(func(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
		return action, nil
	})

	chain := NewInterceptorChain(normalizer, passthrough, logger)

	// Create an mcp.Message
	sess := testSession()
	msg := newToolCallMessage("read_file", map[string]interface{}{"path": "/tmp"}, sess)

	// Run through chain
	result, err := chain.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}

	if result == nil {
		t.Fatal("Intercept() returned nil message")
	}

	// The message should come out unchanged
	if result != msg {
		t.Error("expected the same mcp.Message to come out")
	}
}

func TestInterceptorChain_Error(t *testing.T) {
	normalizer := NewMCPNormalizer()
	logger := testLogger()

	expectedErr := errors.New("policy denied: blocked")

	// Mock ActionInterceptor that returns error
	errInterceptor := ActionInterceptorFunc(func(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
		return nil, expectedErr
	})

	chain := NewInterceptorChain(normalizer, errInterceptor, logger)

	sess := testSession()
	msg := newToolCallMessage("exec_cmd", map[string]interface{}{}, sess)

	result, err := chain.Intercept(context.Background(), msg)
	if err == nil {
		t.Fatal("Intercept() should return error")
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf("error = %v, want %v", err, expectedErr)
	}
	if result != nil {
		t.Error("result should be nil on error")
	}
}

func TestInterceptorChain_MultipleInterceptors(t *testing.T) {
	normalizer := NewMCPNormalizer()
	logger := testLogger()

	// Track which interceptors were called and in what order
	var callOrder []string

	// First mock: a legacy MessageInterceptor wrapped in LegacyAdapter
	first := &mockMessageInterceptor{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			callOrder = append(callOrder, "first")
			return msg, nil
		},
	}

	// Second mock: another legacy MessageInterceptor wrapped in LegacyAdapter
	second := &mockMessageInterceptor{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			callOrder = append(callOrder, "second")
			return msg, nil
		},
	}

	// Chain: first adapter calls second adapter
	// Build the chain by nesting: second is the "next" that first calls
	// But LegacyAdapter doesn't have "next" — it wraps a single MessageInterceptor.
	// To chain, we need to create a composite MessageInterceptor that calls first then second.
	compositeInterceptor := &mockMessageInterceptor{
		interceptFn: func(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
			msg, err := first.Intercept(ctx, msg)
			if err != nil {
				return nil, err
			}
			return second.Intercept(ctx, msg)
		},
	}

	adapter := NewLegacyAdapter(compositeInterceptor, "composite-chain")
	chain := NewInterceptorChain(normalizer, adapter, logger)

	sess := testSession()
	msg := newToolCallMessage("read_file", map[string]interface{}{}, sess)

	result, err := chain.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil result")
	}

	// Verify both were called in order
	if len(callOrder) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(callOrder))
	}
	if callOrder[0] != "first" {
		t.Errorf("first call = %q, want 'first'", callOrder[0])
	}
	if callOrder[1] != "second" {
		t.Errorf("second call = %q, want 'second'", callOrder[1])
	}
}

func TestInterceptorChain_NormalizeError(t *testing.T) {
	normalizer := NewMCPNormalizer()
	logger := testLogger()

	passthrough := ActionInterceptorFunc(func(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
		return action, nil
	})

	chain := NewInterceptorChain(normalizer, passthrough, logger)

	// Pass a non-mcp.Message — should fail normalization
	// InterceptorChain.Intercept expects *mcp.Message, but Normalizer.Normalize expects interface{}
	// We can't directly trigger this through InterceptorChain.Intercept since it takes *mcp.Message
	// So test that a nil message doesn't panic
	msg := &mcp.Message{
		Direction: mcp.ClientToServer,
		Timestamp: time.Now(),
	}

	result, err := chain.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("Intercept() error = %v", err)
	}
	// nil decoded message should still pass through as a passthrough action
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestInterceptorChain_ImplementsMessageInterceptor(t *testing.T) {
	// Compile-time check is in chain.go, but verify at runtime too
	normalizer := NewMCPNormalizer()
	logger := testLogger()
	passthrough := ActionInterceptorFunc(func(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
		return action, nil
	})

	chain := NewInterceptorChain(normalizer, passthrough, logger)

	// Verify it can be used as a proxy.MessageInterceptor
	msg := newToolCallMessage("test", map[string]interface{}{}, testSession())
	_, err := chain.Intercept(context.Background(), msg)
	if err != nil {
		t.Fatalf("chain used as MessageInterceptor failed: %v", err)
	}
}
