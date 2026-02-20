package action

import (
	"context"
	"errors"
	"testing"
)

func TestActionInterceptorFunc_SatisfiesInterface(t *testing.T) {
	// Verify that ActionInterceptorFunc satisfies ActionInterceptor at compile time.
	var _ ActionInterceptor = ActionInterceptorFunc(nil)
}

func TestActionInterceptorFunc_Passthrough(t *testing.T) {
	fn := ActionInterceptorFunc(func(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
		return action, nil
	})

	action := &CanonicalAction{
		Type: ActionToolCall,
		Name: "test-tool",
	}

	result, err := fn.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result != action {
		t.Fatal("expected same action returned")
	}
	if result.Name != "test-tool" {
		t.Fatalf("expected name 'test-tool', got %q", result.Name)
	}
}

func TestActionInterceptorFunc_Error(t *testing.T) {
	expectedErr := errors.New("interceptor error")
	fn := ActionInterceptorFunc(func(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
		return nil, expectedErr
	})

	_, err := fn.Intercept(context.Background(), &CanonicalAction{})
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected error %v, got %v", expectedErr, err)
	}
}

func TestActionInterceptorFunc_ModifiesAction(t *testing.T) {
	fn := ActionInterceptorFunc(func(ctx context.Context, action *CanonicalAction) (*CanonicalAction, error) {
		action.Name = "modified"
		return action, nil
	})

	action := &CanonicalAction{Name: "original"}
	result, err := fn.Intercept(context.Background(), action)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if result.Name != "modified" {
		t.Fatalf("expected name 'modified', got %q", result.Name)
	}
}
