// Package config provides configuration loading for Sentinel Gate OSS.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/viper"
)

// InitViper initializes Viper with the configuration file and environment variables.
// If configFile is empty, it searches for sentinel-gate.yaml/.yml in standard locations.
// The search requires an explicit YAML extension to avoid matching the binary itself,
// which Viper's built-in SetConfigName would match (same base name, no extension).
func InitViper(configFile string) {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else if found := findConfigFile(); found != "" {
		viper.SetConfigFile(found)
	} else {
		// No config file found in any standard location.
		// Set name/type without search paths so ReadInConfig returns
		// ConfigFileNotFoundError (handled gracefully by callers).
		viper.SetConfigName("sentinel-gate")
		viper.SetConfigType("yaml")
	}

	// Environment variable support: SENTINEL_GATE_SERVER_HTTP_ADDR
	viper.SetEnvPrefix("SENTINEL_GATE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	// Bind nested keys for env var support
	bindNestedEnvKeys()
}

// findConfigFile searches standard locations for a sentinel-gate config file
// with an explicit YAML extension (.yaml or .yml). This prevents Viper from
// matching the binary "sentinel-gate" (no extension) in the current directory.
func findConfigFile() string {
	home, _ := os.UserHomeDir()
	paths := []string{
		".",
		filepath.Join(home, ".sentinel-gate"),
	}
	if runtime.GOOS == "windows" {
		// %ProgramData%\sentinel-gate (typically C:\ProgramData\sentinel-gate)
		if pd := os.Getenv("ProgramData"); pd != "" {
			paths = append(paths, filepath.Join(pd, "sentinel-gate"))
		}
	} else {
		paths = append(paths, "/etc/sentinel-gate")
	}
	return findConfigFileInPaths(paths)
}

// findConfigFileInPaths searches the given directories for sentinel-gate.yaml or .yml.
// Returns the full path of the first match, or empty string if none found.
func findConfigFileInPaths(paths []string) string {
	for _, dir := range paths {
		for _, ext := range []string{".yaml", ".yml"} {
			path := filepath.Join(dir, "sentinel-gate"+ext)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}
	return ""
}

// bindNestedEnvKeys binds all OSS config keys for environment variable support.
// This enables overriding nested config values via environment variables.
// Example: SENTINEL_GATE_SERVER_HTTP_ADDR overrides server.http_addr
func bindNestedEnvKeys() {
	// L-6: Check errors from BindEnv and log warnings for failures.
	// These are non-fatal — env var overrides just won't work for that key.
	bindEnv := func(key string) {
		if err := viper.BindEnv(key); err != nil {
			slog.Warn("failed to bind environment variable", "key", key, "error", err)
		}
	}

	// Server config
	bindEnv("server.http_addr")
	bindEnv("server.session_timeout")
	bindEnv("server.log_level")

	// Upstream config (mutually exclusive: http OR command)
	bindEnv("upstream.http")
	bindEnv("upstream.command")
	bindEnv("upstream.http_timeout")
	// Note: upstream.args is an array, handled by Viper's env parsing

	// Auth config
	// Note: auth.identities and auth.api_keys are arrays, complex to override via env
	// Users should use config file for these

	// Audit config
	bindEnv("audit.output")
	bindEnv("audit.channel_size")
	bindEnv("audit.batch_size")
	bindEnv("audit.buffer_size")
	bindEnv("audit.warning_threshold")
	bindEnv("audit.flush_interval")
	bindEnv("audit.send_timeout")

	// Audit file config (L-44)
	bindEnv("audit_file.dir")
	bindEnv("audit_file.retention_days")
	bindEnv("audit_file.max_file_size_mb")
	bindEnv("audit_file.cache_size")

	// Rate limit config
	bindEnv("rate_limit.enabled")
	bindEnv("rate_limit.ip_rate")
	bindEnv("rate_limit.user_rate")
	bindEnv("rate_limit.ip_burst")
	bindEnv("rate_limit.user_burst")
	bindEnv("rate_limit.cleanup_interval")
	bindEnv("rate_limit.max_ttl")

	// Evidence config
	bindEnv("evidence.enabled")
	bindEnv("evidence.key_path")
	bindEnv("evidence.output_path")
	bindEnv("evidence.signer_id")

	// Webhook config
	bindEnv("webhook.url")
	bindEnv("webhook.secret")
	bindEnv("webhook.events") // L-46: Bind webhook.events for env var override

	// Note: policies is an array, complex to override via env
	// Users should use config file for policies
}

// LoadConfig reads the configuration file, applies environment overrides,
// sets defaults, and returns the OSSConfig.
func LoadConfig() (*OSSConfig, error) {
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found - continue with env vars only
		// This allows running with pure environment variable configuration
	}

	var cfg OSSConfig
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	applyPreDefaults(&cfg)
	cfg.SetDefaults()

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// LoadConfigRaw reads the configuration file and applies defaults,
// but does NOT validate. Use this when CLI flags may override
// config values before validation.
func LoadConfigRaw() (*OSSConfig, error) {
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	var cfg OSSConfig
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	applyPreDefaults(&cfg)
	cfg.SetDefaults()
	return &cfg, nil
}

func applyPreDefaults(cfg *OSSConfig) {
	if viper.IsSet("rate_limit.enabled") {
		cfg.rateLimitEnabledExplicit = true
	}
	if viper.IsSet("evidence.enabled") {
		cfg.evidenceEnabledExplicit = true
	}
}

// ConfigFileUsed returns the path to the configuration file that was loaded.
// Returns an empty string if no config file was found (env vars only mode).
func ConfigFileUsed() string {
	return viper.ConfigFileUsed()
}
