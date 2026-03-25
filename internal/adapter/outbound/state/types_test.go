package state

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppStateDefaults(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewFileStateStore(filepath.Join(t.TempDir(), "state.json"), logger)
	st := store.DefaultState()

	if st.Version != "1" {
		t.Errorf("expected Version '1', got %q", st.Version)
	}
	if st.DefaultPolicy != "deny" {
		t.Errorf("expected DefaultPolicy 'deny', got %q", st.DefaultPolicy)
	}
	if st.Upstreams == nil {
		t.Error("expected Upstreams to be non-nil empty slice")
	}
	if len(st.Upstreams) != 0 {
		t.Errorf("expected 0 upstreams, got %d", len(st.Upstreams))
	}
	if st.Policies == nil {
		t.Error("expected Policies to be non-nil empty slice")
	}
	if len(st.Policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(st.Policies))
	}
	if st.Identities == nil {
		t.Error("expected Identities to be non-nil empty slice")
	}
	if len(st.Identities) != 0 {
		t.Errorf("expected 0 identities, got %d", len(st.Identities))
	}
	if st.APIKeys == nil {
		t.Error("expected APIKeys to be non-nil empty slice")
	}
	if len(st.APIKeys) != 0 {
		t.Errorf("expected 0 API keys, got %d", len(st.APIKeys))
	}
	if st.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
	if st.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set")
	}
}

func TestAppStateSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(48 * time.Hour)

	original := &AppState{
		Version:       "1",
		DefaultPolicy: "allow",
		Upstreams: []UpstreamEntry{
			{
				ID:      "u-1",
				Name:    "test-upstream",
				Type:    "http",
				Enabled: true,
				URL:     "http://localhost:8080/mcp",
			},
		},
		Policies: []PolicyEntry{
			{
				ID:          "p-1",
				Name:        "allow-reads",
				Priority:    5,
				ToolPattern: "read_*",
				Action:      "allow",
				Enabled:     true,
			},
		},
		Identities: []IdentityEntry{
			{
				ID:    "id-1",
				Name:  "alice",
				Roles: []string{"admin", "user"},
			},
		},
		APIKeys: []APIKeyEntry{
			{
				ID:         "k-1",
				KeyHash:    "argon2:keyhash",
				IdentityID: "id-1",
				Name:       "alice-key",
				ExpiresAt:  &expires,
			},
		},
		AdminPasswordHash: "argon2:adminhash",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var restored AppState
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if restored.Version != original.Version {
		t.Errorf("Version: got %q, want %q", restored.Version, original.Version)
	}
	if restored.DefaultPolicy != original.DefaultPolicy {
		t.Errorf("DefaultPolicy: got %q, want %q", restored.DefaultPolicy, original.DefaultPolicy)
	}
	if len(restored.Upstreams) != 1 {
		t.Fatalf("expected 1 upstream, got %d", len(restored.Upstreams))
	}
	if restored.Upstreams[0].URL != "http://localhost:8080/mcp" {
		t.Errorf("upstream URL: got %q", restored.Upstreams[0].URL)
	}
	if len(restored.Policies) != 1 || restored.Policies[0].ToolPattern != "read_*" {
		t.Errorf("policy mismatch after round trip")
	}
	if len(restored.Identities) != 1 || restored.Identities[0].Name != "alice" {
		t.Errorf("identity mismatch after round trip")
	}
	if len(restored.APIKeys) != 1 || restored.APIKeys[0].KeyHash != "argon2:keyhash" {
		t.Errorf("API key mismatch after round trip")
	}
	if restored.APIKeys[0].ExpiresAt == nil || !restored.APIKeys[0].ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt mismatch after round trip")
	}
	if restored.AdminPasswordHash != "argon2:adminhash" {
		t.Errorf("AdminPasswordHash: got %q", restored.AdminPasswordHash)
	}
}

func TestAppStateVersion(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := NewFileStateStore(filepath.Join(t.TempDir(), "state.json"), logger)
	st := store.DefaultState()

	if st.Version != "1" {
		t.Errorf("expected Version '1', got %q", st.Version)
	}
}

func TestConfigTypes_QuotaConfigEntry(t *testing.T) {
	q := QuotaConfigEntry{
		IdentityID:         "user-42",
		MaxCallsPerSession: 100,
		MaxWritesPerSession: 20,
		MaxDeletesPerSession: 5,
		MaxCallsPerMinute:  10,
		MaxCallsPerDay:     500,
		ToolLimits:         map[string]int64{"write_file": 15, "delete_file": 3},
		Action:             "deny",
		Enabled:            true,
	}

	if q.IdentityID != "user-42" {
		t.Errorf("IdentityID: got %q", q.IdentityID)
	}
	if q.MaxCallsPerSession != 100 {
		t.Errorf("MaxCallsPerSession: got %d", q.MaxCallsPerSession)
	}
	if q.MaxWritesPerSession != 20 {
		t.Errorf("MaxWritesPerSession: got %d", q.MaxWritesPerSession)
	}
	if q.MaxDeletesPerSession != 5 {
		t.Errorf("MaxDeletesPerSession: got %d", q.MaxDeletesPerSession)
	}
	if q.MaxCallsPerMinute != 10 {
		t.Errorf("MaxCallsPerMinute: got %d", q.MaxCallsPerMinute)
	}
	if q.MaxCallsPerDay != 500 {
		t.Errorf("MaxCallsPerDay: got %d", q.MaxCallsPerDay)
	}
	if q.ToolLimits["write_file"] != 15 {
		t.Errorf("ToolLimits[write_file]: got %d", q.ToolLimits["write_file"])
	}
	if q.ToolLimits["delete_file"] != 3 {
		t.Errorf("ToolLimits[delete_file]: got %d", q.ToolLimits["delete_file"])
	}
	if q.Action != "deny" {
		t.Errorf("Action: got %q", q.Action)
	}
	if !q.Enabled {
		t.Error("expected Enabled to be true")
	}
}

func TestConfigTypes_DriftConfigEntry(t *testing.T) {
	d := DriftConfigEntry{
		BaselineWindowDays: 14,
		CurrentWindowDays:  1,
		ToolShiftThreshold: 0.20,
		DenyRateThreshold:  0.10,
		ErrorRateThreshold: 0.10,
		LatencyThreshold:   0.50,
		TemporalThreshold:  0.30,
		ArgShiftThreshold:  0.30,
		MinCallsBaseline:   10,
	}

	if d.BaselineWindowDays != 14 {
		t.Errorf("BaselineWindowDays: got %d", d.BaselineWindowDays)
	}
	if d.CurrentWindowDays != 1 {
		t.Errorf("CurrentWindowDays: got %d", d.CurrentWindowDays)
	}
	if d.ToolShiftThreshold != 0.20 {
		t.Errorf("ToolShiftThreshold: got %f", d.ToolShiftThreshold)
	}
	if d.DenyRateThreshold != 0.10 {
		t.Errorf("DenyRateThreshold: got %f", d.DenyRateThreshold)
	}
	if d.ErrorRateThreshold != 0.10 {
		t.Errorf("ErrorRateThreshold: got %f", d.ErrorRateThreshold)
	}
	if d.LatencyThreshold != 0.50 {
		t.Errorf("LatencyThreshold: got %f", d.LatencyThreshold)
	}
	if d.TemporalThreshold != 0.30 {
		t.Errorf("TemporalThreshold: got %f", d.TemporalThreshold)
	}
	if d.ArgShiftThreshold != 0.30 {
		t.Errorf("ArgShiftThreshold: got %f", d.ArgShiftThreshold)
	}
	if d.MinCallsBaseline != 10 {
		t.Errorf("MinCallsBaseline: got %d", d.MinCallsBaseline)
	}
}

func TestConfigTypes_FinOpsConfigEntry(t *testing.T) {
	f := FinOpsConfigEntry{
		Enabled:            true,
		DefaultCostPerCall: 0.05,
		ToolCosts:          map[string]float64{"read_file": 0.01, "write_file": 0.10},
		Budgets:            map[string]float64{"user-1": 50.0, "user-2": 100.0},
		AlertThresholds:    []float64{0.70, 0.85, 1.0},
	}

	if !f.Enabled {
		t.Error("expected Enabled to be true")
	}
	if f.DefaultCostPerCall != 0.05 {
		t.Errorf("DefaultCostPerCall: got %f", f.DefaultCostPerCall)
	}
	if f.ToolCosts["read_file"] != 0.01 {
		t.Errorf("ToolCosts[read_file]: got %f", f.ToolCosts["read_file"])
	}
	if f.ToolCosts["write_file"] != 0.10 {
		t.Errorf("ToolCosts[write_file]: got %f", f.ToolCosts["write_file"])
	}
	if f.Budgets["user-1"] != 50.0 {
		t.Errorf("Budgets[user-1]: got %f", f.Budgets["user-1"])
	}
	if f.Budgets["user-2"] != 100.0 {
		t.Errorf("Budgets[user-2]: got %f", f.Budgets["user-2"])
	}
	if len(f.AlertThresholds) != 3 {
		t.Fatalf("expected 3 alert thresholds, got %d", len(f.AlertThresholds))
	}
	if f.AlertThresholds[0] != 0.70 {
		t.Errorf("AlertThresholds[0]: got %f", f.AlertThresholds[0])
	}
}

func TestConfigTypes_RecordingConfigEntry(t *testing.T) {
	r := RecordingConfigEntry{
		Enabled:        true,
		RecordPayloads: true,
		MaxFileSize:    10485760,
		RetentionDays:  30,
		RedactPatterns: []string{`\b\d{3}-\d{2}-\d{4}\b`},
		StorageDir:     "/var/data/recordings",
	}

	if !r.Enabled {
		t.Error("expected Enabled to be true")
	}
	if !r.RecordPayloads {
		t.Error("expected RecordPayloads to be true")
	}
	if r.MaxFileSize != 10485760 {
		t.Errorf("MaxFileSize: got %d", r.MaxFileSize)
	}
	if r.RetentionDays != 30 {
		t.Errorf("RetentionDays: got %d", r.RetentionDays)
	}
	if len(r.RedactPatterns) != 1 {
		t.Fatalf("expected 1 redact pattern, got %d", len(r.RedactPatterns))
	}
	if r.StorageDir != "/var/data/recordings" {
		t.Errorf("StorageDir: got %q", r.StorageDir)
	}
}

func TestConfigTypes_NamespaceConfigEntry(t *testing.T) {
	n := NamespaceConfigEntry{
		Enabled: true,
		Rules: map[string]NamespaceRuleEntry{
			"admin": {
				VisibleTools: []string{"read_file", "write_file", "delete_file"},
			},
			"reader": {
				VisibleTools: []string{"read_file"},
				HiddenTools:  []string{"delete_file"},
			},
		},
	}

	if !n.Enabled {
		t.Error("expected Enabled to be true")
	}
	if len(n.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(n.Rules))
	}
	adminRule, ok := n.Rules["admin"]
	if !ok {
		t.Fatal("missing admin rule")
	}
	if len(adminRule.VisibleTools) != 3 {
		t.Errorf("admin VisibleTools: expected 3, got %d", len(adminRule.VisibleTools))
	}
	readerRule, ok := n.Rules["reader"]
	if !ok {
		t.Fatal("missing reader rule")
	}
	if len(readerRule.VisibleTools) != 1 {
		t.Errorf("reader VisibleTools: expected 1, got %d", len(readerRule.VisibleTools))
	}
	if len(readerRule.HiddenTools) != 1 {
		t.Errorf("reader HiddenTools: expected 1, got %d", len(readerRule.HiddenTools))
	}
}

func TestAppState_JSONRoundTrip(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(72 * time.Hour)

	original := &AppState{
		Version:       "1",
		DefaultPolicy: "deny",
		Upstreams: []UpstreamEntry{
			{
				ID:        "u1",
				Name:      "stdio-server",
				Type:      "stdio",
				Enabled:   true,
				Command:   "/usr/local/bin/mcp",
				Args:      []string{"--verbose"},
				Env:       map[string]string{"PATH": "/usr/bin"},
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		Policies: []PolicyEntry{
			{
				ID:          "p1",
				Name:        "deny-deletes",
				Priority:    1,
				ToolPattern: "delete_*",
				Action:      "deny",
				Enabled:     true,
				HelpText:    "Deletes are not allowed",
				CreatedAt:   now,
				UpdatedAt:   now,
			},
		},
		Identities: []IdentityEntry{
			{
				ID:        "i1",
				Name:      "bob",
				Roles:     []string{"user"},
				CreatedAt: now,
				UpdatedAt: now,
			},
		},
		APIKeys: []APIKeyEntry{
			{
				ID:         "k1",
				KeyHash:    "argon2:hash123",
				KeyPrefix:  "sk-abcde",
				IdentityID: "i1",
				Name:       "bob-key",
				CreatedAt:  now,
				ExpiresAt:  &expires,
			},
		},
		ContentScanningConfig: &ContentScanningConfig{
			Mode:             "enforce",
			Enabled:          true,
			InputScanEnabled: true,
			PatternActions:   map[string]string{"email": "mask", "us_ssn": "block"},
			UpdatedAt:        now,
		},
		Quotas: []QuotaConfigEntry{
			{
				IdentityID:         "i1",
				MaxCallsPerSession: 200,
				MaxCallsPerDay:     1000,
				Action:             "warn",
				Enabled:            true,
			},
		},
		RecordingConfig: &RecordingConfigEntry{
			Enabled:        true,
			RecordPayloads: false,
			RetentionDays:  7,
			StorageDir:     "/tmp/recordings",
		},
		TelemetryConfig: &TelemetryConfigEntry{
			Enabled:     true,
			ServiceName: "sentinel-gate",
			UpdatedAt:   now,
		},
		NamespaceConfig: &NamespaceConfigEntry{
			Enabled: true,
			Rules: map[string]NamespaceRuleEntry{
				"admin": {VisibleTools: []string{"*"}},
			},
			UpdatedAt: now,
		},
		FinOpsConfig: &FinOpsConfigEntry{
			Enabled:            true,
			DefaultCostPerCall: 0.02,
			ToolCosts:          map[string]float64{"write_file": 0.05},
			Budgets:            map[string]float64{"i1": 25.0},
			AlertThresholds:    []float64{0.80, 1.0},
			UpdatedAt:          now,
		},
		HealthConfig: &HealthConfigEntry{
			DenyRateWarning:    0.30,
			DenyRateCritical:   0.50,
			DriftScoreWarning:  0.40,
			DriftScoreCritical: 0.70,
			ErrorRateWarning:   0.10,
			ErrorRateCritical:  0.25,
		},
		PermissionHealthConfig: &PermissionHealthConfigEntry{
			Mode:            "shadow",
			LearningDays:    14,
			GracePeriodDays: 7,
			WhitelistTools:  []string{"health_check"},
			UpdatedAt:       now,
		},
		DriftConfig: &DriftConfigEntry{
			BaselineWindowDays: 14,
			CurrentWindowDays:  1,
			ToolShiftThreshold: 0.20,
			DenyRateThreshold:  0.10,
			ErrorRateThreshold: 0.10,
			LatencyThreshold:   0.50,
			TemporalThreshold:  0.30,
			ArgShiftThreshold:  0.30,
			MinCallsBaseline:   10,
			UpdatedAt:          now,
		},
		AdminPasswordHash: "argon2:fulltest",
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	data, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent failed: %v", err)
	}

	var restored AppState
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Top-level fields
	if restored.Version != "1" {
		t.Errorf("Version: got %q", restored.Version)
	}
	if restored.DefaultPolicy != "deny" {
		t.Errorf("DefaultPolicy: got %q", restored.DefaultPolicy)
	}
	if restored.AdminPasswordHash != "argon2:fulltest" {
		t.Errorf("AdminPasswordHash: got %q", restored.AdminPasswordHash)
	}

	// Upstreams
	if len(restored.Upstreams) != 1 {
		t.Fatalf("Upstreams: expected 1, got %d", len(restored.Upstreams))
	}
	if restored.Upstreams[0].Command != "/usr/local/bin/mcp" {
		t.Errorf("Upstream Command: got %q", restored.Upstreams[0].Command)
	}
	if restored.Upstreams[0].Env["PATH"] != "/usr/bin" {
		t.Errorf("Upstream Env: got %v", restored.Upstreams[0].Env)
	}

	// Policies
	if len(restored.Policies) != 1 {
		t.Fatalf("Policies: expected 1, got %d", len(restored.Policies))
	}
	if restored.Policies[0].HelpText != "Deletes are not allowed" {
		t.Errorf("Policy HelpText: got %q", restored.Policies[0].HelpText)
	}

	// Identities
	if len(restored.Identities) != 1 || restored.Identities[0].Name != "bob" {
		t.Errorf("Identity mismatch: %v", restored.Identities)
	}

	// API Keys
	if len(restored.APIKeys) != 1 {
		t.Fatalf("APIKeys: expected 1, got %d", len(restored.APIKeys))
	}
	if restored.APIKeys[0].KeyPrefix != "sk-abcde" {
		t.Errorf("APIKey KeyPrefix: got %q", restored.APIKeys[0].KeyPrefix)
	}
	if restored.APIKeys[0].ExpiresAt == nil || !restored.APIKeys[0].ExpiresAt.Equal(expires) {
		t.Errorf("APIKey ExpiresAt mismatch")
	}

	// ContentScanningConfig
	if restored.ContentScanningConfig == nil {
		t.Fatal("ContentScanningConfig is nil after round trip")
	}
	if restored.ContentScanningConfig.Mode != "enforce" {
		t.Errorf("ContentScanningConfig.Mode: got %q", restored.ContentScanningConfig.Mode)
	}
	if !restored.ContentScanningConfig.InputScanEnabled {
		t.Error("ContentScanningConfig.InputScanEnabled: expected true")
	}
	if restored.ContentScanningConfig.PatternActions["us_ssn"] != "block" {
		t.Errorf("ContentScanningConfig.PatternActions[us_ssn]: got %q", restored.ContentScanningConfig.PatternActions["us_ssn"])
	}

	// Quotas
	if len(restored.Quotas) != 1 {
		t.Fatalf("Quotas: expected 1, got %d", len(restored.Quotas))
	}
	if restored.Quotas[0].MaxCallsPerSession != 200 {
		t.Errorf("Quota MaxCallsPerSession: got %d", restored.Quotas[0].MaxCallsPerSession)
	}
	if restored.Quotas[0].Action != "warn" {
		t.Errorf("Quota Action: got %q", restored.Quotas[0].Action)
	}

	// RecordingConfig
	if restored.RecordingConfig == nil {
		t.Fatal("RecordingConfig is nil after round trip")
	}
	if restored.RecordingConfig.RetentionDays != 7 {
		t.Errorf("RecordingConfig.RetentionDays: got %d", restored.RecordingConfig.RetentionDays)
	}

	// TelemetryConfig
	if restored.TelemetryConfig == nil {
		t.Fatal("TelemetryConfig is nil after round trip")
	}
	if restored.TelemetryConfig.ServiceName != "sentinel-gate" {
		t.Errorf("TelemetryConfig.ServiceName: got %q", restored.TelemetryConfig.ServiceName)
	}

	// NamespaceConfig
	if restored.NamespaceConfig == nil {
		t.Fatal("NamespaceConfig is nil after round trip")
	}
	if !restored.NamespaceConfig.Enabled {
		t.Error("NamespaceConfig.Enabled: expected true")
	}
	if _, ok := restored.NamespaceConfig.Rules["admin"]; !ok {
		t.Error("NamespaceConfig missing admin rule")
	}

	// FinOpsConfig
	if restored.FinOpsConfig == nil {
		t.Fatal("FinOpsConfig is nil after round trip")
	}
	if restored.FinOpsConfig.DefaultCostPerCall != 0.02 {
		t.Errorf("FinOpsConfig.DefaultCostPerCall: got %f", restored.FinOpsConfig.DefaultCostPerCall)
	}
	if restored.FinOpsConfig.ToolCosts["write_file"] != 0.05 {
		t.Errorf("FinOpsConfig.ToolCosts[write_file]: got %f", restored.FinOpsConfig.ToolCosts["write_file"])
	}
	if restored.FinOpsConfig.Budgets["i1"] != 25.0 {
		t.Errorf("FinOpsConfig.Budgets[i1]: got %f", restored.FinOpsConfig.Budgets["i1"])
	}

	// HealthConfig
	if restored.HealthConfig == nil {
		t.Fatal("HealthConfig is nil after round trip")
	}
	if restored.HealthConfig.DenyRateWarning != 0.30 {
		t.Errorf("HealthConfig.DenyRateWarning: got %f", restored.HealthConfig.DenyRateWarning)
	}
	if restored.HealthConfig.ErrorRateCritical != 0.25 {
		t.Errorf("HealthConfig.ErrorRateCritical: got %f", restored.HealthConfig.ErrorRateCritical)
	}

	// PermissionHealthConfig
	if restored.PermissionHealthConfig == nil {
		t.Fatal("PermissionHealthConfig is nil after round trip")
	}
	if restored.PermissionHealthConfig.Mode != "shadow" {
		t.Errorf("PermissionHealthConfig.Mode: got %q", restored.PermissionHealthConfig.Mode)
	}
	if restored.PermissionHealthConfig.LearningDays != 14 {
		t.Errorf("PermissionHealthConfig.LearningDays: got %d", restored.PermissionHealthConfig.LearningDays)
	}

	// DriftConfig
	if restored.DriftConfig == nil {
		t.Fatal("DriftConfig is nil after round trip")
	}
	if restored.DriftConfig.BaselineWindowDays != 14 {
		t.Errorf("DriftConfig.BaselineWindowDays: got %d", restored.DriftConfig.BaselineWindowDays)
	}
	if restored.DriftConfig.MinCallsBaseline != 10 {
		t.Errorf("DriftConfig.MinCallsBaseline: got %d", restored.DriftConfig.MinCallsBaseline)
	}

	// Timestamps
	if !restored.CreatedAt.Equal(now) {
		t.Errorf("CreatedAt mismatch: got %v, want %v", restored.CreatedAt, now)
	}
}
