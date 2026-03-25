package recording

import (
	"errors"
	"regexp"
	"strings"
)

const (
	// DefaultMaxFileSize is 100 MB.
	DefaultMaxFileSize = int64(100 * 1024 * 1024)
	// DefaultRetentionDays is 30 days.
	DefaultRetentionDays = 30
	// DefaultStorageDir is the default directory for JSONL recording files.
	DefaultStorageDir = "recordings"
)

// RecordingConfig controls the session recording subsystem.
type RecordingConfig struct {
	// Enabled enables or disables session recording globally.
	Enabled bool `json:"enabled"`
	// RecordPayloads controls whether tool arguments and responses are stored.
	// When false, RequestArgs and ResponseBody are always omitted from events (RECD-09).
	RecordPayloads bool `json:"record_payloads"`
	// MaxFileSize is the maximum size in bytes for a single JSONL file.
	// 0 means unlimited.
	MaxFileSize int64 `json:"max_file_size"`
	// RetentionDays is how many days to keep recording files.
	// 0 means keep forever.
	RetentionDays int `json:"retention_days"`
	// RedactPatterns are regex patterns applied to string payloads before writing
	// when RecordPayloads=true. Matches are replaced with [REDACTED].
	RedactPatterns []string `json:"redact_patterns"`
	// StorageDir is the directory where JSONL files are stored.
	StorageDir string `json:"storage_dir"`
	// AutoRedactPII enables automatic redaction of PII patterns (email, credit card,
	// SSN, phone, API keys, etc.) in recorded payloads. When true, built-in PII
	// patterns are applied in addition to any user-defined RedactPatterns.
	// Only effective when RecordPayloads is also true.
	AutoRedactPII bool `json:"auto_redact_pii"`
}

// DefaultConfig returns a RecordingConfig with sensible defaults.
// Recording is disabled by default; operators must explicitly enable it.
func DefaultConfig() RecordingConfig {
	return RecordingConfig{
		Enabled:        false,
		RecordPayloads: false,
		MaxFileSize:    DefaultMaxFileSize,
		RetentionDays:  DefaultRetentionDays,
		RedactPatterns: nil,
		StorageDir:     DefaultStorageDir,
	}
}

// Validate checks the configuration for correctness.
// Returns a non-nil error if any field is invalid.
func (c *RecordingConfig) Validate() error {
	if c.StorageDir == "" {
		return errors.New("recording: storage_dir must not be empty")
	}
	if strings.Contains(c.StorageDir, "..") {
		return errors.New("recording: storage_dir must not contain '..'")
	}
	// Absolute paths are allowed: boot code resolves relative paths to absolute
	// after initial validation. Re-validation of live config must not reject them.
	// M-15: Reject well-known sensitive system directories.
	if strings.HasPrefix(c.StorageDir, "/") {
		for _, sensitive := range []string{"/etc", "/var/run", "/proc", "/sys", "/dev", "/boot", "/sbin", "/bin", "/usr"} {
			if c.StorageDir == sensitive || strings.HasPrefix(c.StorageDir, sensitive+"/") {
				return errors.New("recording: storage_dir must not point to system directory " + sensitive)
			}
		}
	}
	if c.RetentionDays < 0 {
		return errors.New("recording: retention_days must be >= 0")
	}
	if c.MaxFileSize < 0 {
		return errors.New("recording: max_file_size must be >= 0")
	}
	for i, pattern := range c.RedactPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return errors.New("recording: redact_patterns[" + itoa(i) + "] invalid regex: " + err.Error())
		}
	}
	return nil
}

// itoa converts a non-negative int to its decimal string representation.
// Used to avoid importing strconv for a small helper.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
