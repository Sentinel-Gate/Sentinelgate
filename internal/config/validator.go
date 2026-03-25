package config

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
)

// RegisterCustomValidators registers OSS-specific validation rules.
// Must be called before validating OSSConfig.
func RegisterCustomValidators(v *validator.Validate) error {
	// audit_output: validates "stdout" or "file://<absolute-path>"
	if err := v.RegisterValidation("audit_output", validateAuditOutput); err != nil {
		return fmt.Errorf("failed to register audit_output validator: %w", err)
	}
	return nil
}

// validateAuditOutput validates the audit output field.
// Valid values: "stdout" or "file://<absolute-path>"
func validateAuditOutput(fl validator.FieldLevel) bool {
	output := fl.Field().String()

	// "stdout" is always valid
	if output == "stdout" {
		return true
	}

	// "file://<path>" requires an absolute path.
	// Accept both native absolute paths and URI-style paths starting with "/"
	// (e.g., file:///var/log/audit.log) for cross-platform compatibility.
	if strings.HasPrefix(output, "file://") {
		path := strings.TrimPrefix(output, "file://")
		return path != "" && (filepath.IsAbs(path) || strings.HasPrefix(path, "/"))
	}

	return false
}

// Validate validates the OSSConfig using struct tags and custom cross-field rules.
// Returns an error if validation fails, with actionable error messages.
func (c *OSSConfig) Validate() error {
	// Create validator with required struct enabled
	v := validator.New(validator.WithRequiredStructEnabled())

	// Register custom validators
	if err := RegisterCustomValidators(v); err != nil {
		return err
	}

	// Run struct validation (tags)
	if err := v.Struct(c); err != nil {
		return formatValidationErrors(err)
	}

	// Cross-field validation: Upstream mutual exclusion
	if err := c.validateUpstreamMutualExclusion(); err != nil {
		return err
	}

	// Cross-field validation: Identity reference integrity
	if err := c.validateIdentityReferences(); err != nil {
		return err
	}

	// L-40: Validate duration fields reject invalid formats instead of silently using defaults.
	if err := c.validateDurations(); err != nil {
		return err
	}

	// L-41: Validate AuditFileConfig numeric bounds.
	if err := c.validateAuditFileConfig(); err != nil {
		return err
	}

	// L-42: Convert relative evidence paths to absolute for consistent resolution.
	c.resolveEvidencePaths()

	return nil
}

// validateUpstreamMutualExclusion ensures at most one of HTTP or Command is set.
// In multi-upstream mode (state.json), both can be empty -- upstreams come from state.json.
func (c *OSSConfig) validateUpstreamMutualExclusion() error {
	hasHTTP := c.Upstream.HTTP != ""
	hasCommand := c.Upstream.Command != ""

	if hasHTTP && hasCommand {
		return errors.New("upstream: specify http OR command, not both")
	}

	// Both empty is OK -- multi-upstream mode uses state.json for upstream config.
	return nil
}

// HasYAMLUpstream returns true if the YAML config has a single upstream configured.
func (c *OSSConfig) HasYAMLUpstream() bool {
	return c.Upstream.HTTP != "" || c.Upstream.Command != ""
}

// validateIdentityReferences ensures all API key identity_id values reference valid identities.
func (c *OSSConfig) validateIdentityReferences() error {
	// Build map of known identity IDs
	knownIdentities := make(map[string]struct{}, len(c.Auth.Identities))
	for _, identity := range c.Auth.Identities {
		knownIdentities[identity.ID] = struct{}{}
	}

	// Check each API key references a known identity
	for i, apiKey := range c.Auth.APIKeys {
		if _, exists := knownIdentities[apiKey.IdentityID]; !exists {
			return fmt.Errorf("api_keys[%d]: references unknown identity_id: %s", i, apiKey.IdentityID)
		}
	}

	return nil
}

// formatValidationErrors converts validator.ValidationErrors to user-friendly messages.
func formatValidationErrors(err error) error {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		var messages []string
		for _, e := range validationErrors {
			msg := formatSingleValidationError(e)
			messages = append(messages, msg)
		}
		return errors.New(strings.Join(messages, "; "))
	}
	return err
}

// formatSingleValidationError creates a user-friendly message for a single validation error.
func formatSingleValidationError(e validator.FieldError) string {
	field := e.Namespace()
	tag := e.Tag()

	switch tag {
	case "required":
		return fmt.Sprintf("%s is required", field)
	case "min":
		return fmt.Sprintf("%s must have at least %s items", field, e.Param())
	case "oneof":
		return fmt.Sprintf("%s must be one of: %s", field, e.Param())
	case "startswith":
		return fmt.Sprintf("%s must start with %q", field, e.Param())
	case "url":
		return fmt.Sprintf("%s must be a valid URL", field)
	case "hostname_port":
		return fmt.Sprintf("%s must be a valid host:port", field)
	case "audit_output":
		return fmt.Sprintf("%s must be 'stdout' or 'file://<absolute-path>'", field)
	default:
		return fmt.Sprintf("%s failed validation: %s", field, tag)
	}
}

// validateDuration checks that a duration string is valid and non-negative per time.ParseDuration.
// Empty strings are allowed (defaults are applied before validation).
func validateDuration(field, value string) error {
	if value == "" {
		return nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return fmt.Errorf("%s: invalid duration %q: %w", field, value, err)
	}
	// L-69: Reject negative durations.
	if d < 0 {
		return fmt.Errorf("%s: duration must not be negative: %q", field, value)
	}
	return nil
}

// validateDurations validates all duration fields in the config.
// L-40: Values like "30minutes" are rejected instead of silently falling back to defaults.
func (c *OSSConfig) validateDurations() error {
	checks := []struct {
		field string
		value string
	}{
		{"server.session_timeout", c.Server.SessionTimeout},
		{"upstream.http_timeout", c.Upstream.HTTPTimeout},
		{"audit.flush_interval", c.Audit.FlushInterval},
		{"audit.send_timeout", c.Audit.SendTimeout},
		{"rate_limit.cleanup_interval", c.RateLimit.CleanupInterval},
		{"rate_limit.max_ttl", c.RateLimit.MaxTTL},
	}
	for _, chk := range checks {
		if err := validateDuration(chk.field, chk.value); err != nil {
			return err
		}
	}
	return nil
}

// validateAuditFileConfig checks AuditFileConfig numeric bounds.
// L-41: Reject negative RetentionDays and non-positive MaxFileSizeMB.
func (c *OSSConfig) validateAuditFileConfig() error {
	if c.AuditFile.RetentionDays < 0 {
		return fmt.Errorf("audit_file.retention_days must be >= 0, got %d", c.AuditFile.RetentionDays)
	}
	if c.AuditFile.MaxFileSizeMB < 0 {
		return fmt.Errorf("audit_file.max_file_size_mb must be >= 0, got %d", c.AuditFile.MaxFileSizeMB)
	}
	return nil
}

// resolveEvidencePaths converts relative evidence paths to absolute paths.
// L-42: Ensures consistent path resolution regardless of working directory changes.
func (c *OSSConfig) resolveEvidencePaths() {
	if c.Evidence.KeyPath != "" && !filepath.IsAbs(c.Evidence.KeyPath) {
		if abs, err := filepath.Abs(c.Evidence.KeyPath); err == nil {
			c.Evidence.KeyPath = abs
		}
	}
	if c.Evidence.OutputPath != "" && !filepath.IsAbs(c.Evidence.OutputPath) {
		if abs, err := filepath.Abs(c.Evidence.OutputPath); err == nil {
			c.Evidence.OutputPath = abs
		}
	}
}
