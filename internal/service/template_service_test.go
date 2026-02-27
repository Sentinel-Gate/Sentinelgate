package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
)

func newTestTemplateService(t *testing.T) *TemplateService {
	t.Helper()
	adminSvc, _, _, _ := testPolicyAdminEnv(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return NewTemplateService(adminSvc, logger)
}

func TestTemplateService_List(t *testing.T) {
	svc := newTestTemplateService(t)
	templates := svc.List()
	if got := len(templates); got != 7 {
		t.Errorf("List() returned %d templates, want 7", got)
	}
}

func TestTemplateService_Get_Found(t *testing.T) {
	svc := newTestTemplateService(t)
	tmpl, err := svc.Get("safe-coding")
	if err != nil {
		t.Fatalf("Get(\"safe-coding\") unexpected error: %v", err)
	}
	if tmpl.ID != "safe-coding" {
		t.Errorf("Get().ID = %q, want %q", tmpl.ID, "safe-coding")
	}
	if tmpl.Name != "Safe Coding" {
		t.Errorf("Get().Name = %q, want %q", tmpl.Name, "Safe Coding")
	}
}

func TestTemplateService_Get_NotFound(t *testing.T) {
	svc := newTestTemplateService(t)
	_, err := svc.Get("nope")
	if err == nil {
		t.Fatal("Get(\"nope\") should return error")
	}
	if !errors.Is(err, ErrTemplateNotFound) {
		t.Errorf("Get(\"nope\") error = %v, want ErrTemplateNotFound", err)
	}
}

func TestTemplateService_Apply_Success(t *testing.T) {
	adminSvc, _, _, _ := testPolicyAdminEnv(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewTemplateService(adminSvc, logger)
	ctx := context.Background()

	created, err := svc.Apply(ctx, "read-only")
	if err != nil {
		t.Fatalf("Apply(\"read-only\") unexpected error: %v", err)
	}

	// Must have an ID assigned by PolicyAdminService.
	if created.ID == "" {
		t.Error("Apply() policy has no ID")
	}

	// Name must match the template.
	if created.Name != "Read Only" {
		t.Errorf("Apply().Name = %q, want %q", created.Name, "Read Only")
	}

	// Must have the correct number of rules (read-only has 2).
	if len(created.Rules) != 2 {
		t.Errorf("Apply().Rules count = %d, want 2", len(created.Rules))
	}

	// Policy must be retrievable from the store.
	got, err := adminSvc.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get() after Apply() unexpected error: %v", err)
	}
	if got.Name != "Read Only" {
		t.Errorf("Stored policy Name = %q, want %q", got.Name, "Read Only")
	}
}

func TestTemplateService_Apply_NotFound(t *testing.T) {
	svc := newTestTemplateService(t)
	ctx := context.Background()

	_, err := svc.Apply(ctx, "nope")
	if err == nil {
		t.Fatal("Apply(\"nope\") should return error")
	}
	if !errors.Is(err, ErrTemplateNotFound) {
		t.Errorf("Apply(\"nope\") error = %v, want ErrTemplateNotFound", err)
	}
}

func TestTemplateService_Apply_CreatesIndependentPolicy(t *testing.T) {
	adminSvc, _, _, _ := testPolicyAdminEnv(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewTemplateService(adminSvc, logger)
	ctx := context.Background()

	// Apply the same template twice.
	first, err := svc.Apply(ctx, "lockdown")
	if err != nil {
		t.Fatalf("First Apply() unexpected error: %v", err)
	}
	second, err := svc.Apply(ctx, "lockdown")
	if err != nil {
		t.Fatalf("Second Apply() unexpected error: %v", err)
	}

	// Must have distinct IDs.
	if first.ID == second.ID {
		t.Errorf("Two applies of the same template produced the same ID: %q", first.ID)
	}

	// Both must be retrievable.
	if _, err := adminSvc.Get(ctx, first.ID); err != nil {
		t.Errorf("First policy not found after second apply: %v", err)
	}
	if _, err := adminSvc.Get(ctx, second.ID); err != nil {
		t.Errorf("Second policy not found: %v", err)
	}
}
