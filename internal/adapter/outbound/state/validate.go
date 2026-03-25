package state

import (
	"log/slog"
	"strings"
)

// validateState checks loaded state for provably invalid values and corrects them.
// It only fixes states that are clearly wrong (negative counts, unknown enums).
// Zero values are intentional and never replaced with defaults.
func validateState(st *AppState, logger *slog.Logger) {
	if st.ContentScanningConfig != nil {
		validateContentScanningConfig(st.ContentScanningConfig, logger)
	}
	if st.PermissionHealthConfig != nil {
		validatePermissionHealthConfig(st.PermissionHealthConfig, logger)
	}
	for i := range st.Quotas {
		validateQuotaEntry(&st.Quotas[i], logger)
	}
	if st.RecordingConfig != nil {
		validateRecordingConfig(st.RecordingConfig, logger)
	}
	if st.DriftConfig != nil {
		validateDriftConfig(st.DriftConfig, logger)
	}
	if st.FinOpsConfig != nil {
		validateFinOpsConfig(st.FinOpsConfig, logger)
	}
}

func validateContentScanningConfig(c *ContentScanningConfig, logger *slog.Logger) {
	switch c.Mode {
	case "", "monitor", "enforce":
		// Valid (empty means not explicitly set, leave as-is).
	default:
		logger.Warn("invalid content scanning mode, resetting to monitor", "mode", c.Mode)
		c.Mode = "monitor"
	}
}

func validatePermissionHealthConfig(c *PermissionHealthConfigEntry, logger *slog.Logger) {
	switch c.Mode {
	case "", "disabled", "shadow", "suggest", "auto":
		// Valid.
	default:
		logger.Warn("invalid permission health mode, resetting to disabled", "mode", c.Mode)
		c.Mode = "disabled"
	}
	if c.LearningDays < 0 {
		logger.Warn("negative learning_days in permission health config, resetting to 0", "value", c.LearningDays)
		c.LearningDays = 0
	}
	if c.GracePeriodDays < 0 {
		logger.Warn("negative grace_period_days in permission health config, resetting to 0", "value", c.GracePeriodDays)
		c.GracePeriodDays = 0
	}
}

func validateQuotaEntry(q *QuotaConfigEntry, logger *slog.Logger) {
	switch q.Action {
	case "deny", "warn":
		// Valid.
	default:
		logger.Warn("invalid quota action, resetting to deny", "identity_id", q.IdentityID, "action", q.Action)
		q.Action = "deny"
	}
	if q.MaxCallsPerSession < 0 {
		logger.Warn("negative max_calls_per_session, resetting to 0", "identity_id", q.IdentityID)
		q.MaxCallsPerSession = 0
	}
	if q.MaxWritesPerSession < 0 {
		logger.Warn("negative max_writes_per_session, resetting to 0", "identity_id", q.IdentityID)
		q.MaxWritesPerSession = 0
	}
	if q.MaxDeletesPerSession < 0 {
		logger.Warn("negative max_deletes_per_session, resetting to 0", "identity_id", q.IdentityID)
		q.MaxDeletesPerSession = 0
	}
	if q.MaxCallsPerMinute < 0 {
		logger.Warn("negative max_calls_per_minute, resetting to 0", "identity_id", q.IdentityID)
		q.MaxCallsPerMinute = 0
	}
	if q.MaxCallsPerDay < 0 {
		logger.Warn("negative max_calls_per_day, resetting to 0", "identity_id", q.IdentityID)
		q.MaxCallsPerDay = 0
	}
	for name, limit := range q.ToolLimits {
		if limit < 0 {
			logger.Warn("negative tool limit, resetting to 0", "identity_id", q.IdentityID, "tool", name)
			q.ToolLimits[name] = 0
		}
	}
}

func validateRecordingConfig(c *RecordingConfigEntry, logger *slog.Logger) {
	if c.RetentionDays < 0 {
		logger.Warn("negative retention_days in recording config, resetting to 0")
		c.RetentionDays = 0
	}
	if c.MaxFileSize < 0 {
		logger.Warn("negative max_file_size in recording config, resetting to 0")
		c.MaxFileSize = 0
	}
	if strings.Contains(c.StorageDir, "..") {
		logger.Warn("recording storage_dir contains '..', clearing", "value", c.StorageDir)
		c.StorageDir = ""
	}
}

func validateDriftConfig(c *DriftConfigEntry, logger *slog.Logger) {
	if c.BaselineWindowDays < 0 {
		logger.Warn("negative baseline_window_days in drift config, resetting to 0")
		c.BaselineWindowDays = 0
	}
	if c.CurrentWindowDays < 0 {
		logger.Warn("negative current_window_days in drift config, resetting to 0")
		c.CurrentWindowDays = 0
	}
	if c.MinCallsBaseline < 0 {
		logger.Warn("negative min_calls_baseline in drift config, resetting to 0")
		c.MinCallsBaseline = 0
	}
	if c.ToolShiftThreshold < 0 {
		logger.Warn("negative tool_shift_threshold in drift config, resetting to 0")
		c.ToolShiftThreshold = 0
	}
	if c.DenyRateThreshold < 0 {
		logger.Warn("negative deny_rate_threshold in drift config, resetting to 0")
		c.DenyRateThreshold = 0
	}
	if c.ErrorRateThreshold < 0 {
		logger.Warn("negative error_rate_threshold in drift config, resetting to 0")
		c.ErrorRateThreshold = 0
	}
	if c.LatencyThreshold < 0 {
		logger.Warn("negative latency_threshold in drift config, resetting to 0")
		c.LatencyThreshold = 0
	}
	if c.TemporalThreshold < 0 {
		logger.Warn("negative temporal_threshold in drift config, resetting to 0")
		c.TemporalThreshold = 0
	}
	if c.ArgShiftThreshold < 0 {
		logger.Warn("negative arg_shift_threshold in drift config, resetting to 0")
		c.ArgShiftThreshold = 0
	}
}

func validateFinOpsConfig(c *FinOpsConfigEntry, logger *slog.Logger) {
	if c.DefaultCostPerCall < 0 {
		logger.Warn("negative default_cost_per_call in finops config, resetting to 0")
		c.DefaultCostPerCall = 0
	}
	for name, cost := range c.ToolCosts {
		if cost < 0 {
			logger.Warn("negative tool cost in finops config, resetting to 0", "tool", name)
			c.ToolCosts[name] = 0
		}
	}
	for id, budget := range c.Budgets {
		if budget < 0 {
			logger.Warn("negative budget in finops config, resetting to 0", "identity_id", id)
			c.Budgets[id] = 0
		}
	}
	for i, threshold := range c.AlertThresholds {
		if threshold < 0 {
			logger.Warn("negative alert threshold in finops config, resetting to 0", "index", i)
			c.AlertThresholds[i] = 0
		}
	}
}
