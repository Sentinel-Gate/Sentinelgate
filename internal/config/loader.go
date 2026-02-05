// Package config provides configuration loading for Sentinel Gate OSS.
package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

// InitViper initializes Viper with the configuration file and environment variables.
// If configFile is empty, it searches for sentinel-gate.yaml in standard locations.
func InitViper(configFile string) {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("sentinel-gate")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.sentinel-gate")
		viper.AddConfigPath("/etc/sentinel-gate")
	}

	// Environment variable support: SENTINEL_GATE_SERVER_HTTP_ADDR
	viper.SetEnvPrefix("SENTINEL_GATE")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	// Bind nested keys for env var support
	bindNestedEnvKeys()
}

// bindNestedEnvKeys binds all OSS config keys for environment variable support.
// This enables overriding nested config values via environment variables.
// Example: SENTINEL_GATE_SERVER_HTTP_ADDR overrides server.http_addr
func bindNestedEnvKeys() {
	// Server config
	_ = viper.BindEnv("server.http_addr")
	_ = viper.BindEnv("server.session_timeout")
	_ = viper.BindEnv("server.log_level")

	// Upstream config (mutually exclusive: http OR command)
	_ = viper.BindEnv("upstream.http")
	_ = viper.BindEnv("upstream.command")
	_ = viper.BindEnv("upstream.http_timeout")
	// Note: upstream.args is an array, handled by Viper's env parsing

	// Auth config
	// Note: auth.identities and auth.api_keys are arrays, complex to override via env
	// Users should use config file for these

	// Audit config
	_ = viper.BindEnv("audit.output")

	// Rate limit config
	_ = viper.BindEnv("rate_limit.enabled")
	_ = viper.BindEnv("rate_limit.ip_rate")
	_ = viper.BindEnv("rate_limit.user_rate")
	_ = viper.BindEnv("rate_limit.cleanup_interval")
	_ = viper.BindEnv("rate_limit.max_ttl")

	// Note: policies is an array, complex to override via env
	// Users should use config file for policies

	// Dev mode
	_ = viper.BindEnv("dev_mode")
}

// LoadConfig reads the configuration file, applies environment overrides,
// sets defaults, and returns the OSSConfig.
// Note: Caller should apply any CLI flag overrides (e.g. --dev), then call
// cfg.SetDevDefaults() and cfg.Validate() to complete initialization.
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

	// Apply default values for optional fields
	cfg.SetDefaults()

	// In dev mode, apply permissive defaults before validation
	cfg.SetDevDefaults()

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// LoadConfigRaw reads the configuration file and applies defaults,
// but does NOT apply dev defaults or validate.
// Use this when CLI flags may override DevMode before validation.
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

	cfg.SetDefaults()
	return &cfg, nil
}

// ConfigFileUsed returns the path to the configuration file that was loaded.
// Returns an empty string if no config file was found (env vars only mode).
func ConfigFileUsed() string {
	return viper.ConfigFileUsed()
}
