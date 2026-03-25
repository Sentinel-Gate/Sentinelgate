package recording

import (
	"strings"
	"testing"
)

func TestRecordingConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	if err := cfg.Validate(); err != nil {
		t.Errorf("DefaultConfig().Validate() = %v, want nil", err)
	}

	if cfg.Enabled {
		t.Error("DefaultConfig().Enabled = true, want false")
	}
	if cfg.RecordPayloads {
		t.Error("DefaultConfig().RecordPayloads = true, want false")
	}
	if cfg.MaxFileSize != DefaultMaxFileSize {
		t.Errorf("DefaultConfig().MaxFileSize = %d, want %d", cfg.MaxFileSize, DefaultMaxFileSize)
	}
	if cfg.RetentionDays != DefaultRetentionDays {
		t.Errorf("DefaultConfig().RetentionDays = %d, want %d", cfg.RetentionDays, DefaultRetentionDays)
	}
	if cfg.StorageDir != DefaultStorageDir {
		t.Errorf("DefaultConfig().StorageDir = %q, want %q", cfg.StorageDir, DefaultStorageDir)
	}
}

func TestRecordingConfig_Validate_Valid(t *testing.T) {
	cfg := &RecordingConfig{
		Enabled:        true,
		RecordPayloads: true,
		MaxFileSize:    50 * 1024 * 1024,
		RetentionDays:  90,
		RedactPatterns: []string{`\b\d{3}-\d{2}-\d{4}\b`, `password\s*=\s*\S+`},
		StorageDir:     "/data/recordings",
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for valid config", err)
	}
}

func TestRecordingConfig_Validate_InvalidRegex(t *testing.T) {
	cfg := &RecordingConfig{
		StorageDir:     "recordings",
		RedactPatterns: []string{`[invalid`},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for invalid regex")
	}
	if !strings.Contains(err.Error(), "invalid regex") {
		t.Errorf("Validate() error = %q, want it to mention 'invalid regex'", err.Error())
	}
	if !strings.Contains(err.Error(), "redact_patterns[0]") {
		t.Errorf("Validate() error = %q, want it to mention 'redact_patterns[0]'", err.Error())
	}
}

func TestRecordingConfig_Validate_ValidRegex(t *testing.T) {
	cfg := &RecordingConfig{
		StorageDir: "recordings",
		RedactPatterns: []string{
			`\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b`,
			`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b`,
			`(?i)api[_-]?key\s*[:=]\s*\S+`,
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for valid regex patterns", err)
	}
}

func TestRecordingConfig_Validate_EmptyStorageDir(t *testing.T) {
	cfg := &RecordingConfig{
		StorageDir: "",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for empty StorageDir")
	}
	if !strings.Contains(err.Error(), "storage_dir must not be empty") {
		t.Errorf("Validate() error = %q, want mention of 'storage_dir must not be empty'", err.Error())
	}
}

func TestRecordingConfig_Validate_TraversalStorageDir(t *testing.T) {
	cfg := &RecordingConfig{
		StorageDir: "../../../etc/shadow",
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for '..' in StorageDir")
	}
	if !strings.Contains(err.Error(), "..") {
		t.Errorf("Validate() error = %q, want mention of '..'", err.Error())
	}
}

func TestRecordingConfig_Validate_SensitiveSystemDir(t *testing.T) {
	sensitives := []string{"/etc", "/etc/secrets", "/proc", "/sys", "/dev", "/boot", "/bin", "/usr", "/usr/local"}

	for _, dir := range sensitives {
		cfg := &RecordingConfig{
			StorageDir: dir,
		}

		err := cfg.Validate()
		if err == nil {
			t.Errorf("Validate() = nil for StorageDir=%q, want error for system directory", dir)
		}
	}
}

func TestRecordingConfig_Validate_NegativeRetentionDays(t *testing.T) {
	cfg := &RecordingConfig{
		StorageDir:    "recordings",
		RetentionDays: -1,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for negative RetentionDays")
	}
	if !strings.Contains(err.Error(), "retention_days") {
		t.Errorf("Validate() error = %q, want mention of 'retention_days'", err.Error())
	}
}

func TestRecordingConfig_Validate_NegativeMaxFileSize(t *testing.T) {
	cfg := &RecordingConfig{
		StorageDir:  "recordings",
		MaxFileSize: -1,
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for negative MaxFileSize")
	}
	if !strings.Contains(err.Error(), "max_file_size") {
		t.Errorf("Validate() error = %q, want mention of 'max_file_size'", err.Error())
	}
}

func TestRecordingConfig_Validate_MultipleInvalidRegex(t *testing.T) {
	// Only the first invalid pattern should trigger the error (validation stops at first).
	cfg := &RecordingConfig{
		StorageDir:     "recordings",
		RedactPatterns: []string{`valid\d+`, `[bad`, `(also-bad`},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() = nil, want error for invalid regex")
	}
	if !strings.Contains(err.Error(), "redact_patterns[1]") {
		t.Errorf("Validate() error = %q, want mention of 'redact_patterns[1]'", err.Error())
	}
}

func TestRecordingConfig_Validate_ZeroValues(t *testing.T) {
	// Zero MaxFileSize and RetentionDays are valid (meaning unlimited/forever).
	cfg := &RecordingConfig{
		StorageDir:    "recordings",
		MaxFileSize:   0,
		RetentionDays: 0,
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil for zero MaxFileSize and RetentionDays", err)
	}
}
