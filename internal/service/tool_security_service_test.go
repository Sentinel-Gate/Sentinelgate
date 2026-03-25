package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// setupToolSecurityTest creates a ToolSecurityService backed by a temporary state file.
func setupToolSecurityTest(t *testing.T) (*ToolSecurityService, *upstream.ToolCache, *state.FileStateStore) {
	t.Helper()
	tmpDir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	stateStore := state.NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)
	if err := stateStore.Save(stateStore.DefaultState()); err != nil {
		t.Fatalf("save default state: %v", err)
	}
	toolCache := upstream.NewToolCache()
	svc := NewToolSecurityService(toolCache, stateStore, logger)
	return svc, toolCache, stateStore
}

// seedTools populates the tool cache with two sample tools.
func seedTools(cache *upstream.ToolCache) {
	cache.SetToolsForUpstream("upstream-1", []*upstream.DiscoveredTool{
		{Name: "read_file", Description: "Read a file", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "write_file", Description: "Write a file", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})
}

func TestToolSecurityService_CaptureBaseline(t *testing.T) {
	svc, cache, _ := setupToolSecurityTest(t)
	seedTools(cache)

	count, err := svc.CaptureBaseline(context.Background())
	if err != nil {
		t.Fatalf("CaptureBaseline() error = %v", err)
	}
	if count != 2 {
		t.Errorf("CaptureBaseline() count = %d, want 2", count)
	}

	baseline := svc.GetBaseline()
	if len(baseline) != 2 {
		t.Errorf("GetBaseline() len = %d, want 2", len(baseline))
	}
	if _, ok := baseline["read_file"]; !ok {
		t.Error("baseline missing read_file")
	}
	if _, ok := baseline["write_file"]; !ok {
		t.Error("baseline missing write_file")
	}
}

func TestToolSecurityService_CaptureBaseline_NoTools(t *testing.T) {
	svc, _, _ := setupToolSecurityTest(t)

	_, err := svc.CaptureBaseline(context.Background())
	if err == nil {
		t.Fatal("CaptureBaseline() expected error for empty cache, got nil")
	}
}

func TestToolSecurityService_DetectDrift_NoBaseline(t *testing.T) {
	svc, cache, _ := setupToolSecurityTest(t)
	seedTools(cache)

	_, err := svc.DetectDrift(context.Background())
	if err == nil {
		t.Fatal("DetectDrift() expected error when no baseline, got nil")
	}
	if !errors.Is(err, ErrNoBaseline) {
		t.Errorf("DetectDrift() error = %v, want ErrNoBaseline", err)
	}
}

func TestToolSecurityService_DetectDrift_NoChanges(t *testing.T) {
	svc, cache, _ := setupToolSecurityTest(t)
	seedTools(cache)

	if _, err := svc.CaptureBaseline(context.Background()); err != nil {
		t.Fatalf("CaptureBaseline() error = %v", err)
	}

	drifts, err := svc.DetectDrift(context.Background())
	if err != nil {
		t.Fatalf("DetectDrift() error = %v", err)
	}
	if len(drifts) != 0 {
		t.Errorf("DetectDrift() found %d drifts, want 0", len(drifts))
	}
}

func TestToolSecurityService_DetectDrift_AddedTool(t *testing.T) {
	svc, cache, _ := setupToolSecurityTest(t)
	seedTools(cache)

	if _, err := svc.CaptureBaseline(context.Background()); err != nil {
		t.Fatalf("CaptureBaseline() error = %v", err)
	}

	// Add a new tool after baseline capture.
	cache.SetToolsForUpstream("upstream-2", []*upstream.DiscoveredTool{
		{Name: "delete_file", Description: "Delete a file", UpstreamID: "upstream-2", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	drifts, err := svc.DetectDrift(context.Background())
	if err != nil {
		t.Fatalf("DetectDrift() error = %v", err)
	}

	var found bool
	for _, d := range drifts {
		if d.ToolName == "delete_file" && d.DriftType == "added" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DetectDrift() did not report delete_file as added; drifts = %+v", drifts)
	}
}

func TestToolSecurityService_DetectDrift_RemovedTool(t *testing.T) {
	svc, cache, _ := setupToolSecurityTest(t)
	seedTools(cache)

	if _, err := svc.CaptureBaseline(context.Background()); err != nil {
		t.Fatalf("CaptureBaseline() error = %v", err)
	}

	// Remove the upstream, which removes its tools from the cache.
	cache.RemoveUpstream("upstream-1")

	drifts, err := svc.DetectDrift(context.Background())
	if err != nil {
		t.Fatalf("DetectDrift() error = %v", err)
	}

	removedNames := make(map[string]bool)
	for _, d := range drifts {
		if d.DriftType == "removed" {
			removedNames[d.ToolName] = true
		}
	}
	if !removedNames["read_file"] || !removedNames["write_file"] {
		t.Errorf("DetectDrift() removed = %v, want read_file and write_file", removedNames)
	}
}

func TestToolSecurityService_DetectDrift_ChangedTool(t *testing.T) {
	svc, cache, _ := setupToolSecurityTest(t)
	seedTools(cache)

	if _, err := svc.CaptureBaseline(context.Background()); err != nil {
		t.Fatalf("CaptureBaseline() error = %v", err)
	}

	// Re-register the same upstream with a modified tool description.
	cache.SetToolsForUpstream("upstream-1", []*upstream.DiscoveredTool{
		{Name: "read_file", Description: "Read a file (MODIFIED)", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "write_file", Description: "Write a file", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	drifts, err := svc.DetectDrift(context.Background())
	if err != nil {
		t.Fatalf("DetectDrift() error = %v", err)
	}

	var found bool
	for _, d := range drifts {
		if d.ToolName == "read_file" && d.DriftType == "changed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DetectDrift() did not report read_file as changed; drifts = %+v", drifts)
	}
}

func TestToolSecurityService_Quarantine(t *testing.T) {
	svc, _, _ := setupToolSecurityTest(t)

	if err := svc.Quarantine("dangerous_tool"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}

	if !svc.IsQuarantined("dangerous_tool") {
		t.Error("IsQuarantined(dangerous_tool) = false, want true")
	}

	quarantined := svc.GetQuarantinedTools()
	if len(quarantined) != 1 || quarantined[0] != "dangerous_tool" {
		t.Errorf("GetQuarantinedTools() = %v, want [dangerous_tool]", quarantined)
	}
}

func TestToolSecurityService_Unquarantine(t *testing.T) {
	svc, _, _ := setupToolSecurityTest(t)

	if err := svc.Quarantine("dangerous_tool"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}

	if err := svc.Unquarantine("dangerous_tool"); err != nil {
		t.Fatalf("Unquarantine() error = %v", err)
	}

	if svc.IsQuarantined("dangerous_tool") {
		t.Error("IsQuarantined(dangerous_tool) = true after unquarantine, want false")
	}

	quarantined := svc.GetQuarantinedTools()
	if len(quarantined) != 0 {
		t.Errorf("GetQuarantinedTools() = %v, want empty", quarantined)
	}
}

func TestToolSecurityService_Unquarantine_NotQuarantined(t *testing.T) {
	svc, _, _ := setupToolSecurityTest(t)

	err := svc.Unquarantine("unknown_tool")
	if err == nil {
		t.Fatal("Unquarantine() expected error for non-quarantined tool, got nil")
	}
	if !errors.Is(err, ErrNotQuarantined) {
		t.Errorf("Unquarantine() error = %v, want ErrNotQuarantined", err)
	}
}

func TestToolSecurityService_Persistence(t *testing.T) {
	svc, cache, stateStore := setupToolSecurityTest(t)
	seedTools(cache)

	// Capture baseline and quarantine a tool.
	if _, err := svc.CaptureBaseline(context.Background()); err != nil {
		t.Fatalf("CaptureBaseline() error = %v", err)
	}
	if err := svc.Quarantine("read_file"); err != nil {
		t.Fatalf("Quarantine() error = %v", err)
	}

	// Create a new service instance backed by the same state file.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc2 := NewToolSecurityService(cache, stateStore, logger)

	// Load persisted state.
	appState, err := stateStore.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	svc2.LoadFromState(appState)

	// Verify baseline was restored.
	baseline := svc2.GetBaseline()
	if len(baseline) != 2 {
		t.Errorf("restored baseline len = %d, want 2", len(baseline))
	}
	if _, ok := baseline["read_file"]; !ok {
		t.Error("restored baseline missing read_file")
	}

	// Verify quarantine was restored.
	if !svc2.IsQuarantined("read_file") {
		t.Error("restored IsQuarantined(read_file) = false, want true")
	}
}

func TestToolSecurityService_AcceptChange(t *testing.T) {
	svc, cache, _ := setupToolSecurityTest(t)
	seedTools(cache)

	if _, err := svc.CaptureBaseline(context.Background()); err != nil {
		t.Fatalf("CaptureBaseline() error = %v", err)
	}

	// Modify read_file's description.
	cache.SetToolsForUpstream("upstream-1", []*upstream.DiscoveredTool{
		{Name: "read_file", Description: "Read a file (v2)", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
		{Name: "write_file", Description: "Write a file", UpstreamID: "upstream-1", InputSchema: json.RawMessage(`{"type":"object"}`)},
	})

	// Verify drift is detected before accepting.
	drifts, err := svc.DetectDrift(context.Background())
	if err != nil {
		t.Fatalf("DetectDrift() error = %v", err)
	}
	if len(drifts) == 0 {
		t.Fatal("DetectDrift() expected drift for read_file, got none")
	}

	// Accept the change for read_file.
	if err := svc.AcceptChange(context.Background(), "read_file"); err != nil {
		t.Fatalf("AcceptChange() error = %v", err)
	}

	// Verify no more drift for that tool.
	drifts, err = svc.DetectDrift(context.Background())
	if err != nil {
		t.Fatalf("DetectDrift() after accept error = %v", err)
	}
	for _, d := range drifts {
		if d.ToolName == "read_file" {
			t.Errorf("DetectDrift() still reports read_file after AcceptChange: %+v", d)
		}
	}

	// Verify baseline entry was updated.
	baseline := svc.GetBaseline()
	if baseline["read_file"].Description != "Read a file (v2)" {
		t.Errorf("baseline read_file description = %q, want %q",
			baseline["read_file"].Description, "Read a file (v2)")
	}
}
