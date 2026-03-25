package state

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func validationLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestValidateState_NegativeQuota(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.Quotas = []QuotaConfigEntry{{
		IdentityID:         "test",
		Action:             "deny",
		MaxCallsPerSession: -5,
	}}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Quotas) != 1 {
		t.Fatalf("expected 1 quota entry, got %d", len(loaded.Quotas))
	}
	if loaded.Quotas[0].MaxCallsPerSession != 0 {
		t.Errorf("expected MaxCallsPerSession reset to 0, got %d", loaded.Quotas[0].MaxCallsPerSession)
	}
}

func TestValidateState_InvalidQuotaAction(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.Quotas = []QuotaConfigEntry{{
		IdentityID:         "test",
		Action:             "unknown_action",
		MaxCallsPerSession: 10,
	}}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Quotas) != 1 {
		t.Fatalf("expected 1 quota entry, got %d", len(loaded.Quotas))
	}
	if loaded.Quotas[0].Action != "deny" {
		t.Errorf("expected Action reset to 'deny', got %q", loaded.Quotas[0].Action)
	}
}

func TestValidateState_InvalidContentScanMode(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.ContentScanningConfig = &ContentScanningConfig{
		Mode:    "invalid_mode",
		Enabled: true,
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ContentScanningConfig == nil {
		t.Fatal("expected ContentScanningConfig to be present")
	}
	if loaded.ContentScanningConfig.Mode != "monitor" {
		t.Errorf("expected Mode reset to 'monitor', got %q", loaded.ContentScanningConfig.Mode)
	}
}

func TestValidateState_InvalidPermissionHealthMode(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.PermissionHealthConfig = &PermissionHealthConfigEntry{
		Mode:         "bogus",
		LearningDays: 14,
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PermissionHealthConfig == nil {
		t.Fatal("expected PermissionHealthConfig to be present")
	}
	if loaded.PermissionHealthConfig.Mode != "disabled" {
		t.Errorf("expected Mode reset to 'disabled', got %q", loaded.PermissionHealthConfig.Mode)
	}
}

func TestValidateState_NegativeLearningDays(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.PermissionHealthConfig = &PermissionHealthConfigEntry{
		Mode:         "shadow",
		LearningDays: -10,
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PermissionHealthConfig == nil {
		t.Fatal("expected PermissionHealthConfig to be present")
	}
	if loaded.PermissionHealthConfig.LearningDays != 0 {
		t.Errorf("expected LearningDays reset to 0, got %d", loaded.PermissionHealthConfig.LearningDays)
	}
}

func TestValidateState_PathTraversal(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.RecordingConfig = &RecordingConfigEntry{
		Enabled:    true,
		StorageDir: "/var/data/../../../etc/passwd",
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RecordingConfig == nil {
		t.Fatal("expected RecordingConfig to be present")
	}
	if loaded.RecordingConfig.StorageDir != "" {
		t.Errorf("expected StorageDir cleared for path traversal, got %q", loaded.RecordingConfig.StorageDir)
	}
}

func TestValidateState_NegativeRetentionDays(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.RecordingConfig = &RecordingConfigEntry{
		Enabled:       true,
		RetentionDays: -30,
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RecordingConfig == nil {
		t.Fatal("expected RecordingConfig to be present")
	}
	if loaded.RecordingConfig.RetentionDays != 0 {
		t.Errorf("expected RetentionDays reset to 0, got %d", loaded.RecordingConfig.RetentionDays)
	}
}

func TestValidateState_NegativeDriftWindowDays(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.DriftConfig = &DriftConfigEntry{
		BaselineWindowDays: -7,
		CurrentWindowDays:  1,
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DriftConfig == nil {
		t.Fatal("expected DriftConfig to be present")
	}
	if loaded.DriftConfig.BaselineWindowDays != 0 {
		t.Errorf("expected BaselineWindowDays reset to 0, got %d", loaded.DriftConfig.BaselineWindowDays)
	}
}

func TestValidateState_NegativeFinOpsCost(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.FinOpsConfig = &FinOpsConfigEntry{
		Enabled:            true,
		DefaultCostPerCall: -0.50,
		ToolCosts:          map[string]float64{"write_file": -0.10},
		Budgets:            map[string]float64{"user-1": -100.0},
	}
	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.FinOpsConfig == nil {
		t.Fatal("expected FinOpsConfig to be present")
	}
	if loaded.FinOpsConfig.DefaultCostPerCall != 0 {
		t.Errorf("expected DefaultCostPerCall reset to 0, got %f", loaded.FinOpsConfig.DefaultCostPerCall)
	}
	if loaded.FinOpsConfig.ToolCosts["write_file"] != 0 {
		t.Errorf("expected ToolCosts[write_file] reset to 0, got %f", loaded.FinOpsConfig.ToolCosts["write_file"])
	}
	if loaded.FinOpsConfig.Budgets["user-1"] != 0 {
		t.Errorf("expected Budgets[user-1] reset to 0, got %f", loaded.FinOpsConfig.Budgets["user-1"])
	}
}

func TestValidateState_ValidState(t *testing.T) {
	tmpDir := t.TempDir()
	logger := validationLogger()
	store := NewFileStateStore(filepath.Join(tmpDir, "state.json"), logger)

	st := store.DefaultState()
	st.Quotas = []QuotaConfigEntry{{
		IdentityID:         "user-1",
		Action:             "warn",
		MaxCallsPerSession: 100,
		MaxWritesPerSession: 50,
		MaxCallsPerMinute:  10,
		Enabled:            true,
	}}
	st.ContentScanningConfig = &ContentScanningConfig{
		Mode:    "enforce",
		Enabled: true,
	}
	st.PermissionHealthConfig = &PermissionHealthConfigEntry{
		Mode:            "shadow",
		LearningDays:    14,
		GracePeriodDays: 7,
	}
	st.RecordingConfig = &RecordingConfigEntry{
		Enabled:       true,
		RetentionDays: 30,
		StorageDir:    "/var/data/recordings",
	}
	st.DriftConfig = &DriftConfigEntry{
		BaselineWindowDays: 14,
		CurrentWindowDays:  1,
		ToolShiftThreshold: 0.20,
		MinCallsBaseline:   10,
	}
	st.FinOpsConfig = &FinOpsConfigEntry{
		Enabled:            true,
		DefaultCostPerCall: 0.05,
		ToolCosts:          map[string]float64{"read_file": 0.01},
		Budgets:            map[string]float64{"user-1": 50.0},
		AlertThresholds:    []float64{0.80, 1.0},
	}

	if err := store.Save(st); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}

	// Quotas unchanged
	if len(loaded.Quotas) != 1 {
		t.Fatalf("expected 1 quota, got %d", len(loaded.Quotas))
	}
	if loaded.Quotas[0].Action != "warn" {
		t.Errorf("expected Action 'warn', got %q", loaded.Quotas[0].Action)
	}
	if loaded.Quotas[0].MaxCallsPerSession != 100 {
		t.Errorf("expected MaxCallsPerSession 100, got %d", loaded.Quotas[0].MaxCallsPerSession)
	}
	if loaded.Quotas[0].MaxWritesPerSession != 50 {
		t.Errorf("expected MaxWritesPerSession 50, got %d", loaded.Quotas[0].MaxWritesPerSession)
	}

	// ContentScanningConfig unchanged
	if loaded.ContentScanningConfig.Mode != "enforce" {
		t.Errorf("expected Mode 'enforce', got %q", loaded.ContentScanningConfig.Mode)
	}

	// PermissionHealthConfig unchanged
	if loaded.PermissionHealthConfig.Mode != "shadow" {
		t.Errorf("expected Mode 'shadow', got %q", loaded.PermissionHealthConfig.Mode)
	}
	if loaded.PermissionHealthConfig.LearningDays != 14 {
		t.Errorf("expected LearningDays 14, got %d", loaded.PermissionHealthConfig.LearningDays)
	}
	if loaded.PermissionHealthConfig.GracePeriodDays != 7 {
		t.Errorf("expected GracePeriodDays 7, got %d", loaded.PermissionHealthConfig.GracePeriodDays)
	}

	// RecordingConfig unchanged
	if loaded.RecordingConfig.RetentionDays != 30 {
		t.Errorf("expected RetentionDays 30, got %d", loaded.RecordingConfig.RetentionDays)
	}
	if loaded.RecordingConfig.StorageDir != "/var/data/recordings" {
		t.Errorf("expected StorageDir '/var/data/recordings', got %q", loaded.RecordingConfig.StorageDir)
	}

	// DriftConfig unchanged
	if loaded.DriftConfig.BaselineWindowDays != 14 {
		t.Errorf("expected BaselineWindowDays 14, got %d", loaded.DriftConfig.BaselineWindowDays)
	}
	if loaded.DriftConfig.ToolShiftThreshold != 0.20 {
		t.Errorf("expected ToolShiftThreshold 0.20, got %f", loaded.DriftConfig.ToolShiftThreshold)
	}

	// FinOpsConfig unchanged
	if loaded.FinOpsConfig.DefaultCostPerCall != 0.05 {
		t.Errorf("expected DefaultCostPerCall 0.05, got %f", loaded.FinOpsConfig.DefaultCostPerCall)
	}
	if loaded.FinOpsConfig.ToolCosts["read_file"] != 0.01 {
		t.Errorf("expected ToolCosts[read_file] 0.01, got %f", loaded.FinOpsConfig.ToolCosts["read_file"])
	}
	if loaded.FinOpsConfig.Budgets["user-1"] != 50.0 {
		t.Errorf("expected Budgets[user-1] 50.0, got %f", loaded.FinOpsConfig.Budgets["user-1"])
	}
}
