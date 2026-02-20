package config

import (
	"strings"
	"testing"
)

// minimalValidConfig returns a minimal valid OSSConfig for testing.
func minimalValidConfig() *OSSConfig {
	return &OSSConfig{
		Upstream: UpstreamConfig{HTTP: "http://localhost:3000/mcp"},
		Auth: AuthConfig{
			Identities: []IdentityConfig{{ID: "user-1", Name: "Test", Roles: []string{"user"}}},
			APIKeys:    []APIKeyConfig{{KeyHash: "sha256:abc123", IdentityID: "user-1"}},
		},
		Audit:    AuditConfig{Output: "stdout"},
		Policies: []PolicyConfig{{Name: "default", Rules: []RuleConfig{{Name: "allow-all", Condition: "true", Action: "allow"}}}},
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_NoUpstream_MultiUpstreamMode(t *testing.T) {
	t.Parallel()

	// No upstream in YAML is valid -- multi-upstream mode uses state.json.
	cfg := minimalValidConfig()
	cfg.Upstream.HTTP = ""
	cfg.Upstream.Command = ""

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with no upstream (multi-upstream mode) unexpected error: %v", err)
	}
}

func TestHasYAMLUpstream(t *testing.T) {
	t.Parallel()

	cfg := &OSSConfig{}
	if cfg.HasYAMLUpstream() {
		t.Error("HasYAMLUpstream() = true, want false for empty config")
	}

	cfg.Upstream.HTTP = "http://localhost:3000/mcp"
	if !cfg.HasYAMLUpstream() {
		t.Error("HasYAMLUpstream() = false, want true with HTTP set")
	}

	cfg.Upstream.HTTP = ""
	cfg.Upstream.Command = "/usr/bin/mcp-server"
	if !cfg.HasYAMLUpstream() {
		t.Error("HasYAMLUpstream() = false, want true with Command set")
	}
}

func TestValidate_BothUpstreams(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Upstream.HTTP = "http://localhost:3000/mcp"
	cfg.Upstream.Command = "/usr/bin/mcp-server"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("error = %q, want to contain 'not both'", err.Error())
	}
}

func TestValidate_InvalidAuditOutput(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Audit.Output = "invalid"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error, got nil")
	}
	// Error message contains "Audit.Output" and mentions valid formats
	errStr := err.Error()
	if !strings.Contains(errStr, "Audit.Output") {
		t.Errorf("error = %q, want to contain 'Audit.Output'", errStr)
	}
}

func TestValidate_ValidAuditOutputStdout(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Audit.Output = "stdout"

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with stdout unexpected error: %v", err)
	}
}

func TestValidate_ValidAuditOutputFile(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Audit.Output = "file:///var/log/audit.log"

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with file:// unexpected error: %v", err)
	}
}

func TestValidate_InvalidAuditOutputRelativePath(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Audit.Output = "file://relative/path"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for relative path, got nil")
	}
	// Error message contains "Audit.Output" and mentions valid formats
	errStr := err.Error()
	if !strings.Contains(errStr, "Audit.Output") {
		t.Errorf("error = %q, want to contain 'Audit.Output'", errStr)
	}
}

func TestValidate_UnknownIdentityReference(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Auth.APIKeys[0].IdentityID = "unknown-user"

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for unknown identity, got nil")
	}
	if !strings.Contains(err.Error(), "unknown identity_id") {
		t.Errorf("error = %q, want to contain 'unknown identity_id'", err.Error())
	}
}

func TestValidate_MissingIdentities(t *testing.T) {
	t.Parallel()

	// Empty identities is now valid (zero-config mode, managed from admin UI).
	// But if API keys reference nonexistent identities, that should fail.
	cfg := minimalValidConfig()
	cfg.Auth.Identities = nil
	cfg.Auth.APIKeys = nil // Also clear API keys (no dangling refs)

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with empty auth unexpected error: %v", err)
	}
}

func TestValidate_MissingAPIKeys(t *testing.T) {
	t.Parallel()

	// Empty API keys is now valid (zero-config mode, managed from admin UI).
	cfg := minimalValidConfig()
	cfg.Auth.APIKeys = nil

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with empty API keys unexpected error: %v", err)
	}
}

func TestValidate_InvalidKeyHashPrefix(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Auth.APIKeys[0].KeyHash = "abc123" // Missing sha256: prefix

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for missing sha256: prefix, got nil")
	}
	if !strings.Contains(err.Error(), "sha256:") {
		t.Errorf("error = %q, want to contain 'sha256:'", err.Error())
	}
}

func TestValidate_EmptyPolicies(t *testing.T) {
	t.Parallel()

	// Empty policies is valid (default-deny mode).
	// SetDefaults() no longer injects policies -- users create them via admin UI.
	cfg := minimalValidConfig()
	cfg.Policies = nil
	cfg.SetDefaults()

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with empty policies (after defaults) unexpected error: %v", err)
	}
}

func TestValidate_ZeroConfig(t *testing.T) {
	t.Parallel()

	// Simulate a user running "sentinel-gate start" with no config file at all.
	cfg := &OSSConfig{}
	cfg.SetDefaults()

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() zero-config unexpected error: %v", err)
	}

	// Verify defaults were applied -- no default policy (default-deny)
	if len(cfg.Policies) != 0 {
		t.Errorf("expected empty policies (default-deny), got %d policies", len(cfg.Policies))
	}
	if cfg.Audit.Output != "stdout" {
		t.Errorf("default audit output = %q, want 'stdout'", cfg.Audit.Output)
	}
}

func TestValidate_InvalidAction(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Policies[0].Rules[0].Action = "approval_required" // Not valid in OSS

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for invalid action, got nil")
	}
	// Error message mentions Action and valid options
	errStr := err.Error()
	if !strings.Contains(errStr, "Action") || !strings.Contains(errStr, "allow deny") {
		t.Errorf("error = %q, want to contain 'Action' and 'allow deny'", errStr)
	}
}

func TestValidate_CommandUpstream(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Upstream.HTTP = ""
	cfg.Upstream.Command = "/usr/bin/mcp-server"
	cfg.Upstream.Args = []string{"--port", "3000"}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() with command upstream unexpected error: %v", err)
	}
}

func TestValidate_EmptyRoles(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Auth.Identities[0].Roles = nil

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for empty roles, got nil")
	}
}

func TestValidate_EmptyRules(t *testing.T) {
	t.Parallel()

	cfg := minimalValidConfig()
	cfg.Policies[0].Rules = nil

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for empty rules, got nil")
	}
}
