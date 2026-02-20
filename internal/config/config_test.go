package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOSSConfig_SetDefaults(t *testing.T) {
	t.Parallel()

	var cfg OSSConfig
	cfg.SetDefaults()

	if cfg.Server.HTTPAddr != "127.0.0.1:8080" {
		t.Errorf("HTTPAddr = %q, want %q", cfg.Server.HTTPAddr, "127.0.0.1:8080")
	}
	if cfg.Audit.Output != "stdout" {
		t.Errorf("Audit.Output = %q, want %q", cfg.Audit.Output, "stdout")
	}
	if !cfg.RateLimit.Enabled {
		t.Error("RateLimit.Enabled should default to true")
	}
	if cfg.RateLimit.IPRate != 100 {
		t.Errorf("IPRate default = %d, want 100", cfg.RateLimit.IPRate)
	}
}

func TestOSSConfig_SetDefaults_RateLimitEnabled(t *testing.T) {
	t.Parallel()

	var cfg OSSConfig
	cfg.RateLimit.Enabled = true
	cfg.SetDefaults()

	if cfg.RateLimit.IPRate != 100 {
		t.Errorf("IPRate = %d, want 100", cfg.RateLimit.IPRate)
	}
	if cfg.RateLimit.UserRate != 1000 {
		t.Errorf("UserRate = %d, want 1000", cfg.RateLimit.UserRate)
	}
}

func TestOSSConfig_SetDefaults_RateLimitDisabled(t *testing.T) {
	t.Parallel()

	var cfg OSSConfig
	cfg.RateLimit.Enabled = false
	cfg.SetDefaults()

	// Sub-defaults are always populated regardless of Enabled flag,
	// so they're ready if rate limiting is enabled later via API/state.
	if cfg.RateLimit.IPRate != 100 {
		t.Errorf("IPRate = %d, want 100 (sub-defaults always set)", cfg.RateLimit.IPRate)
	}
	if cfg.RateLimit.UserRate != 1000 {
		t.Errorf("UserRate = %d, want 1000 (sub-defaults always set)", cfg.RateLimit.UserRate)
	}
}

func TestOSSConfig_SetDefaults_PreservesExistingValues(t *testing.T) {
	t.Parallel()

	cfg := OSSConfig{
		Server: ServerConfig{
			HTTPAddr: ":9090",
		},
		Audit: AuditConfig{
			Output: "file:///var/log/custom.log",
		},
		RateLimit: RateLimitConfig{
			Enabled:  true,
			IPRate:   50,
			UserRate: 500,
		},
	}

	cfg.SetDefaults()

	// Existing values should be preserved
	if cfg.Server.HTTPAddr != ":9090" {
		t.Errorf("HTTPAddr was overwritten: got %q, want %q", cfg.Server.HTTPAddr, ":9090")
	}
	if cfg.Audit.Output != "file:///var/log/custom.log" {
		t.Errorf("Audit.Output was overwritten: got %q, want %q", cfg.Audit.Output, "file:///var/log/custom.log")
	}
	if cfg.RateLimit.IPRate != 50 {
		t.Errorf("IPRate was overwritten: got %d, want 50", cfg.RateLimit.IPRate)
	}
	if cfg.RateLimit.UserRate != 500 {
		t.Errorf("UserRate was overwritten: got %d, want 500", cfg.RateLimit.UserRate)
	}
}

func TestOSSConfig_SetDefaults_SessionTimeout(t *testing.T) {
	t.Parallel()

	// Test default is applied when empty
	cfg := OSSConfig{}
	cfg.SetDefaults()

	if cfg.Server.SessionTimeout != "30m" {
		t.Errorf("SessionTimeout default: got %q, want %q",
			cfg.Server.SessionTimeout, "30m")
	}

	// Test custom value is preserved
	cfg2 := OSSConfig{
		Server: ServerConfig{SessionTimeout: "1h"},
	}
	cfg2.SetDefaults()

	if cfg2.Server.SessionTimeout != "1h" {
		t.Errorf("SessionTimeout custom: got %q, want %q",
			cfg2.Server.SessionTimeout, "1h")
	}
}

func TestOSSConfig_SetDefaults_HTTPTimeout(t *testing.T) {
	t.Parallel()

	// Test default is applied when empty
	cfg := OSSConfig{}
	cfg.SetDefaults()

	if cfg.Upstream.HTTPTimeout != "30s" {
		t.Errorf("HTTPTimeout default: got %q, want %q",
			cfg.Upstream.HTTPTimeout, "30s")
	}

	// Test custom value is preserved
	cfg2 := OSSConfig{
		Upstream: UpstreamConfig{HTTPTimeout: "60s"},
	}
	cfg2.SetDefaults()

	if cfg2.Upstream.HTTPTimeout != "60s" {
		t.Errorf("HTTPTimeout custom: got %q, want %q",
			cfg2.Upstream.HTTPTimeout, "60s")
	}
}

func TestOSSConfig_SetDefaults_RateLimitDurations(t *testing.T) {
	t.Parallel()

	// Test defaults are applied when rate limiting is enabled
	cfg := OSSConfig{
		RateLimit: RateLimitConfig{Enabled: true},
	}
	cfg.SetDefaults()

	if cfg.RateLimit.CleanupInterval != "5m" {
		t.Errorf("CleanupInterval default: got %q, want %q",
			cfg.RateLimit.CleanupInterval, "5m")
	}
	if cfg.RateLimit.MaxTTL != "1h" {
		t.Errorf("MaxTTL default: got %q, want %q",
			cfg.RateLimit.MaxTTL, "1h")
	}

	// Test custom values are preserved
	cfg2 := OSSConfig{
		RateLimit: RateLimitConfig{
			Enabled:         true,
			CleanupInterval: "10m",
			MaxTTL:          "2h",
		},
	}
	cfg2.SetDefaults()

	if cfg2.RateLimit.CleanupInterval != "10m" {
		t.Errorf("CleanupInterval custom: got %q, want %q",
			cfg2.RateLimit.CleanupInterval, "10m")
	}
	if cfg2.RateLimit.MaxTTL != "2h" {
		t.Errorf("MaxTTL custom: got %q, want %q",
			cfg2.RateLimit.MaxTTL, "2h")
	}

	// Sub-defaults are always populated regardless of Enabled flag
	cfg3 := OSSConfig{
		RateLimit: RateLimitConfig{Enabled: false},
	}
	cfg3.SetDefaults()

	if cfg3.RateLimit.CleanupInterval != "5m" {
		t.Errorf("CleanupInterval = %q, want %q (sub-defaults always set)",
			cfg3.RateLimit.CleanupInterval, "5m")
	}
	if cfg3.RateLimit.MaxTTL != "1h" {
		t.Errorf("MaxTTL = %q, want %q (sub-defaults always set)",
			cfg3.RateLimit.MaxTTL, "1h")
	}
}

func TestFindConfigFileInPaths_EmptyDir(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	got := findConfigFileInPaths([]string{dir})
	if got != "" {
		t.Errorf("findConfigFileInPaths(empty dir) = %q, want empty", got)
	}
}

func TestFindConfigFileInPaths_MatchesYAML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel-gate.yaml")
	_ = os.WriteFile(cfgPath, []byte("server:\n  http_addr: :9090\n"), 0644)

	got := findConfigFileInPaths([]string{dir})
	if got != cfgPath {
		t.Errorf("findConfigFileInPaths = %q, want %q", got, cfgPath)
	}
}

func TestFindConfigFileInPaths_MatchesYML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel-gate.yml")
	_ = os.WriteFile(cfgPath, []byte("server:\n  http_addr: :9090\n"), 0644)

	got := findConfigFileInPaths([]string{dir})
	if got != cfgPath {
		t.Errorf("findConfigFileInPaths = %q, want %q", got, cfgPath)
	}
}

func TestFindConfigFileInPaths_IgnoresNoExtension(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// Simulate the binary: a file named "sentinel-gate" with no extension
	_ = os.WriteFile(filepath.Join(dir, "sentinel-gate"), []byte("\x7fELF binary"), 0755)

	got := findConfigFileInPaths([]string{dir})
	if got != "" {
		t.Errorf("findConfigFileInPaths matched binary = %q, want empty", got)
	}
}

func TestFindConfigFileInPaths_PrefersYAMLOverYML(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "sentinel-gate.yaml")
	ymlPath := filepath.Join(dir, "sentinel-gate.yml")
	_ = os.WriteFile(yamlPath, []byte("server:\n  http_addr: :8080\n"), 0644)
	_ = os.WriteFile(ymlPath, []byte("server:\n  http_addr: :9090\n"), 0644)

	got := findConfigFileInPaths([]string{dir})
	if got != yamlPath {
		t.Errorf("findConfigFileInPaths = %q, want %q (.yaml preferred)", got, yamlPath)
	}
}
