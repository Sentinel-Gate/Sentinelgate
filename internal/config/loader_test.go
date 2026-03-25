package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// resetViper clears all Viper state so tests start fresh.
// Viper uses global state, so each test must reset it.
func resetViper(t *testing.T) {
	t.Helper()
	viper.Reset()
}

func TestLoadConfig_Default(t *testing.T) {
	resetViper(t)

	// Point InitViper at a non-existent file so it falls through to defaults.
	InitViper("")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// Verify SetDefaults was applied.
	if cfg.Server.HTTPAddr != "127.0.0.1:8080" {
		t.Errorf("Server.HTTPAddr = %q, want %q", cfg.Server.HTTPAddr, "127.0.0.1:8080")
	}
	if cfg.Server.LogLevel != "info" {
		t.Errorf("Server.LogLevel = %q, want %q", cfg.Server.LogLevel, "info")
	}
	if cfg.Server.SessionTimeout != "30m" {
		t.Errorf("Server.SessionTimeout = %q, want %q", cfg.Server.SessionTimeout, "30m")
	}
	if cfg.Audit.Output != "stdout" {
		t.Errorf("Audit.Output = %q, want %q", cfg.Audit.Output, "stdout")
	}
	if cfg.Audit.ChannelSize != 1000 {
		t.Errorf("Audit.ChannelSize = %d, want 1000", cfg.Audit.ChannelSize)
	}
	if !cfg.RateLimit.Enabled {
		t.Error("RateLimit.Enabled = false, want true by default")
	}
}

func TestLoadConfig_EnvVars(t *testing.T) {
	resetViper(t)

	t.Setenv("SENTINEL_GATE_SERVER_HTTP_ADDR", "0.0.0.0:9090")
	t.Setenv("SENTINEL_GATE_SERVER_LOG_LEVEL", "debug")

	InitViper("")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Server.HTTPAddr != "0.0.0.0:9090" {
		t.Errorf("Server.HTTPAddr = %q, want %q (from env)", cfg.Server.HTTPAddr, "0.0.0.0:9090")
	}
	if cfg.Server.LogLevel != "debug" {
		t.Errorf("Server.LogLevel = %q, want %q (from env)", cfg.Server.LogLevel, "debug")
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	resetViper(t)

	// Point InitViper at a file that does not exist.
	missingPath := filepath.Join(t.TempDir(), "nonexistent", "sentinel-gate.yaml")
	InitViper(missingPath)

	// ReadInConfig should fail with a real error (not ConfigFileNotFoundError)
	// because we specified an explicit file path that cannot be opened.
	_, err := LoadConfig()
	if err == nil {
		t.Fatal("LoadConfig() expected error for missing explicit config file, got nil")
	}
}

func TestLoadConfig_FromYAMLFile(t *testing.T) {
	resetViper(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel-gate.yaml")
	content := `server:
  http_addr: "0.0.0.0:7070"
  log_level: "warn"
  session_timeout: "1h"
upstream:
  http_timeout: "45s"
audit:
  output: "stdout"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	InitViper(cfgPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Server.HTTPAddr != "0.0.0.0:7070" {
		t.Errorf("Server.HTTPAddr = %q, want %q", cfg.Server.HTTPAddr, "0.0.0.0:7070")
	}
	if cfg.Server.LogLevel != "warn" {
		t.Errorf("Server.LogLevel = %q, want %q", cfg.Server.LogLevel, "warn")
	}
	if cfg.Server.SessionTimeout != "1h" {
		t.Errorf("Server.SessionTimeout = %q, want %q", cfg.Server.SessionTimeout, "1h")
	}
	if cfg.Upstream.HTTPTimeout != "45s" {
		t.Errorf("Upstream.HTTPTimeout = %q, want %q", cfg.Upstream.HTTPTimeout, "45s")
	}
}

func TestLoadConfig_EnvOverridesFile(t *testing.T) {
	resetViper(t)

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sentinel-gate.yaml")
	content := `server:
  http_addr: "127.0.0.1:8080"
  log_level: "info"
audit:
  output: "stdout"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Env var should override the file value.
	t.Setenv("SENTINEL_GATE_SERVER_LOG_LEVEL", "error")

	InitViper(cfgPath)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	if cfg.Server.LogLevel != "error" {
		t.Errorf("Server.LogLevel = %q, want %q (env overrides file)", cfg.Server.LogLevel, "error")
	}
	// File value should still be used for non-overridden fields.
	if cfg.Server.HTTPAddr != "127.0.0.1:8080" {
		t.Errorf("Server.HTTPAddr = %q, want %q (from file)", cfg.Server.HTTPAddr, "127.0.0.1:8080")
	}
}
