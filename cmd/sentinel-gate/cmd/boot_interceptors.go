package cmd

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/quota"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/recording"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/transform"
	"github.com/Sentinel-Gate/Sentinelgate/internal/lifecycle"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// bootInterceptorChain builds the unified native ActionInterceptor chain,
// including content scanning, transforms, outbound control, approval, policy,
// quarantine, rate limiting, quota, audit, auth, and validation (BOOT-07).
// Also sets up session recording as a passive audit observer.
func (bc *bootContext) bootInterceptorChain(ctx context.Context) error {
	// Router adapter (only remaining LegacyAdapter — interfaces with MCP upstream)
	cacheAdapter := proxy.NewToolCacheAdapter(bc.toolCache)
	router := proxy.NewUpstreamRouter(cacheAdapter, bc.upstreamManager, bc.logger)
	bc.upstreamRouter = router // store for late notification forwarder binding

	// Clean up per-upstream I/O mutexes when an upstream is stopped/removed.
	bc.upstreamManager.SetOnStopCallback(router.CleanupUpstream)

	// Namespace isolation (Upgrade 8): filter tools/list by role.
	if bc.namespaceService != nil {
		router.SetNamespaceFilter(bc.namespaceService)
	}

	routerAdapter := action.NewLegacyAdapter(router, "upstream-router")

	// Response scanning (output direction — IPI defense)
	scanMode := action.ScanModeMonitor
	scanEnabled := true
	if bc.appState.ContentScanningConfig != nil {
		// M-30: Validate scan mode from state.json; fallback to "monitor" if unrecognized.
		m := action.ScanMode(bc.appState.ContentScanningConfig.Mode)
		switch m {
		case action.ScanModeMonitor, action.ScanModeEnforce:
			scanMode = m
		default:
			bc.logger.Warn("invalid content scanning mode in state, defaulting to monitor", "mode", bc.appState.ContentScanningConfig.Mode)
		}
		scanEnabled = bc.appState.ContentScanningConfig.Enabled
	}
	bc.responseScanner = action.NewResponseScanner()
	bc.responseScanInterceptor = action.NewResponseScanInterceptor(
		bc.responseScanner, routerAdapter, scanMode, scanEnabled, bc.logger,
	)
	bc.logger.Info("response scanning configured", "mode", scanMode, "enabled", scanEnabled)
	bc.apiHandler.SetResponseScanController(bc.responseScanInterceptor)
	if bc.eventBus != nil {
		bc.responseScanInterceptor.SetEventBus(bc.eventBus)
	}

	// Content scanning (input direction — PII/secrets in arguments)
	inputScanEnabled := true
	if bc.appState.ContentScanningConfig != nil {
		inputScanEnabled = bc.appState.ContentScanningConfig.InputScanEnabled
	}
	bc.contentScanner = action.NewContentScanner()
	bc.contentScanInterceptor = action.NewContentScanInterceptor(
		bc.contentScanner, bc.responseScanInterceptor, inputScanEnabled, bc.logger,
	)
	if bc.eventBus != nil {
		bc.contentScanInterceptor.SetEventBus(bc.eventBus)
	}
	// Load whitelist from state.
	if bc.appState.ContentScanningConfig != nil && len(bc.appState.ContentScanningConfig.Whitelist) > 0 {
		entries := make([]action.WhitelistEntry, 0, len(bc.appState.ContentScanningConfig.Whitelist))
		for _, w := range bc.appState.ContentScanningConfig.Whitelist {
			entries = append(entries, action.WhitelistEntry{
				ID:          w.ID,
				PatternType: action.ContentPatternType(w.PatternType),
				Scope:       action.WhitelistScope(w.Scope),
				Value:       w.Value,
			})
		}
		bc.contentScanInterceptor.SetWhitelist(entries)
	}
	// Load pattern action overrides from state.
	if bc.appState.ContentScanningConfig != nil && len(bc.appState.ContentScanningConfig.PatternActions) > 0 {
		for pt, act := range bc.appState.ContentScanningConfig.PatternActions {
			bc.contentScanner.SetPatternAction(action.ContentPatternType(pt), action.ContentPatternAction(act))
		}
		bc.logger.Info("loaded pattern action overrides", "count", len(bc.appState.ContentScanningConfig.PatternActions))
	}
	bc.logger.Info("input content scanning configured", "enabled", inputScanEnabled)
	bc.apiHandler.SetContentScanInterceptor(bc.contentScanInterceptor)
	if bc.eventBus != nil {
		bc.apiHandler.SetEventBus(bc.eventBus)
	}

	// Transform pipeline
	bc.transformStore = transform.NewMemoryTransformStore()
	bc.transformExecutor = transform.NewTransformExecutor(bc.logger)
	for _, te := range bc.appState.Transforms {
		cfg := transform.TransformConfig{}
		if cfgBytes, err := json.Marshal(te.Config); err == nil {
			if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
				bc.logger.Warn("failed to unmarshal transform config, using empty config",
					"id", te.ID, "name", te.Name, "error", err)
			}
		}
		rule := &transform.TransformRule{
			ID: te.ID, Name: te.Name,
			Type: transform.TransformType(te.Type), ToolMatch: te.ToolMatch,
			Priority: te.Priority, Enabled: te.Enabled, Config: cfg,
			CreatedAt: te.CreatedAt, UpdatedAt: te.UpdatedAt,
		}
		if err := bc.transformStore.Put(ctx, rule); err != nil {
			bc.logger.Warn("failed to store transform rule, skipping",
				"id", te.ID, "name", te.Name, "error", err)
		}
	}
	if len(bc.appState.Transforms) > 0 {
		bc.logger.Info("loaded transform rules", "count", len(bc.appState.Transforms))
	}
	transformInterceptor := transform.NewTransformInterceptor(
		bc.transformStore, bc.transformExecutor, bc.contentScanInterceptor, bc.logger,
	)

	// Session tracker (hoisted for CEL session variables + quota)
	bc.sessionTracker = session.NewSessionTracker(1*time.Minute, session.DefaultClassifier())
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "session-tracker-stop", Phase: lifecycle.PhaseDrainRequests,
		Timeout: 3 * time.Second,
		Fn:      func(ctx context.Context) error { bc.sessionTracker.Stop(); return nil },
	})

	// Approval (HITL)
	bc.approvalStore = action.NewApprovalStore(100)
	if bc.eventBus != nil {
		bc.approvalStore.SetEventBus(bc.eventBus)
	}
	approvalInterceptor := action.NewApprovalInterceptor(bc.approvalStore, transformInterceptor, bc.logger)
	bc.apiHandler.SetApprovalStore(bc.approvalStore)
	// H-4: Cancel all pending approvals during shutdown so blocked goroutines unblock.
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "approval-cancel-all", Phase: lifecycle.PhaseDrainRequests,
		Timeout: 3 * time.Second,
		Fn:      func(ctx context.Context) error { bc.approvalStore.CancelAll(); return nil },
	})

	// Policy + quarantine
	nativePolicyInterceptor := action.NewPolicyActionInterceptor(bc.policyService, approvalInterceptor, bc.logger,
		action.WithSessionUsage(&sessionUsageAdapter{tracker: bc.sessionTracker}),
	)
	bc.policyActionInterceptor = nativePolicyInterceptor // store for late health metrics binding
	quarantineInterceptor := action.NewQuarantineInterceptor(bc.toolSecurityService, nativePolicyInterceptor, bc.logger)

	// Rate limiting
	var ipConfig, userConfig ratelimit.RateLimitConfig
	var preQuotaChain action.ActionInterceptor = quarantineInterceptor

	if bc.cfg.RateLimit.Enabled {
		cleanupInterval, err := time.ParseDuration(bc.cfg.RateLimit.CleanupInterval)
		if err != nil {
			cleanupInterval = 5 * time.Minute
			bc.logger.Warn("invalid rate_limit.cleanup_interval, using default",
				"value", bc.cfg.RateLimit.CleanupInterval, "default", "5m")
		}
		maxTTL, err := time.ParseDuration(bc.cfg.RateLimit.MaxTTL)
		if err != nil {
			maxTTL = 1 * time.Hour
			bc.logger.Warn("invalid rate_limit.max_ttl, using default",
				"value", bc.cfg.RateLimit.MaxTTL, "default", "1h")
		}
		bc.rateLimiter = memory.NewRateLimiterWithConfig(cleanupInterval, maxTTL)
		ipConfig = ratelimit.RateLimitConfig{Rate: bc.cfg.RateLimit.IPRate, Burst: bc.cfg.RateLimit.IPBurst, Period: time.Minute}
		userConfig = ratelimit.RateLimitConfig{Rate: bc.cfg.RateLimit.UserRate, Burst: bc.cfg.RateLimit.UserBurst, Period: time.Minute}
		userRateLimiter := action.NewActionUserRateLimitInterceptor(bc.rateLimiter, userConfig, quarantineInterceptor, bc.logger)
		preQuotaChain = userRateLimiter
		bc.logger.Debug("rate limiting enabled",
			"ip_rate", bc.cfg.RateLimit.IPRate, "user_rate", bc.cfg.RateLimit.UserRate,
			"cleanup_interval", cleanupInterval, "max_ttl", maxTTL)
	} else {
		bc.rateLimiter = memory.NewRateLimiter()
	}

	// Quota enforcement
	bc.quotaStore = quota.NewMemoryQuotaStore()
	for _, qe := range bc.appState.Quotas {
		qcfg := &quota.QuotaConfig{
			IdentityID: qe.IdentityID, MaxCallsPerSession: qe.MaxCallsPerSession,
			MaxWritesPerSession: qe.MaxWritesPerSession, MaxDeletesPerSession: qe.MaxDeletesPerSession,
			MaxCallsPerMinute: qe.MaxCallsPerMinute, MaxCallsPerDay: qe.MaxCallsPerDay,
			ToolLimits: qe.ToolLimits, Action: quota.QuotaAction(qe.Action), Enabled: qe.Enabled,
		}
		// M-29: Validate quota config loaded from state.json before storing.
		if vErr := qcfg.Validate(); vErr != nil {
			bc.logger.Warn("invalid quota config in state, skipping",
				"identity", qe.IdentityID, "error", vErr)
			continue
		}
		if err := bc.quotaStore.Put(ctx, qcfg); err != nil {
			bc.logger.Warn("failed to store quota config, skipping",
				"identity", qe.IdentityID, "error", err)
		}
	}
	if len(bc.appState.Quotas) > 0 {
		bc.logger.Info("loaded quota configurations", "count", len(bc.appState.Quotas))
	}
	quotaService := quota.NewQuotaService(bc.quotaStore, bc.sessionTracker)
	actionQuotaInterceptor := quota.NewActionQuotaInterceptor(quotaService, bc.sessionTracker, preQuotaChain, bc.logger)
	if bc.finopsService != nil {
		actionQuotaInterceptor.SetCostEstimator(bc.finopsService)
	}

	// Wire quota/session/transform into admin API
	bc.apiHandler.SetQuotaStore(bc.quotaStore)
	bc.apiHandler.SetSessionTracker(bc.sessionTracker)
	bc.apiHandler.SetTransformStore(bc.transformStore)
	bc.apiHandler.SetTransformExecutor(bc.transformExecutor)
	// BUG-6 FIX: Wire session service and cache invalidator so Terminate/Revoke/Delete
	// can immediately disconnect agents by flushing the auth interceptor cache.
	bc.apiHandler.SetSessionService(bc.sessionService)

	// Session recording
	bc.bootRecording(ctx, actionQuotaInterceptor)

	// Budget block interceptor (wraps quota — denies calls when monthly budget exceeded)
	var postQuotaChain action.ActionInterceptor = actionQuotaInterceptor
	if bc.finopsService != nil {
		postQuotaChain = service.NewBudgetBlockInterceptor(bc.finopsService, actionQuotaInterceptor, bc.logger)
	}

	// Audit interceptor (wraps budget block)
	// If evidence is enabled, wrap the audit recorder to also produce signed evidence.
	var auditRecorder proxy.AuditRecorder = bc.auditService
	if bc.evidenceService != nil {
		auditRecorder = service.NewEvidenceRecorder(bc.auditService, bc.evidenceService)
	}
	actionAuditInterceptor := action.NewActionAuditInterceptor(auditRecorder, bc.statsService, postQuotaChain, bc.logger)
	actionAuditInterceptor.SetFrameworkGetter(router.ClientFrameworkForSession)
	if bc.recordingObserver != nil {
		actionAuditInterceptor.SetRecordingCallback(bc.recordingObserver.OnAuditRecord)
	}

	// Auth interceptor
	bc.actionAuthInterceptor = action.NewActionAuthInterceptor(bc.apiKeyService, bc.sessionService, actionAuditInterceptor, bc.logger, bc.sessionTracker)
	// BUG-6 FIX: Wire the auth interceptor as session cache invalidator so
	// admin Terminate/Revoke/Delete can flush cached sessions immediately.
	bc.apiHandler.SetSessionCacheInvalidator(bc.actionAuthInterceptor)
	// L-35: Pass context.Background() so the cleanup goroutine stays alive
	// until the explicit Stop() lifecycle hook, rather than exiting early
	// when the signal context is cancelled.
	bc.actionAuthInterceptor.StartCleanup(context.Background())
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "interceptor-drain", Phase: lifecycle.PhaseDrainRequests,
		Timeout: 5 * time.Second,
		Fn: func(ctx context.Context) error {
			actionAuditInterceptor.Drain()
			return nil
		},
	})
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "auth-interceptor-stop", Phase: lifecycle.PhaseDrainRequests,
		Timeout: 3 * time.Second,
		Fn:      func(ctx context.Context) error { bc.actionAuthInterceptor.Stop(); return nil },
	})

	// IP rate limit (optional, before auth)
	var preValidation action.ActionInterceptor = bc.actionAuthInterceptor
	if bc.cfg.RateLimit.Enabled {
		preValidation = action.NewActionIPRateLimitInterceptor(bc.rateLimiter, ipConfig, bc.actionAuthInterceptor, bc.logger)
	}
	// L-36: Pass context.Background() so the cleanup goroutine stays alive
	// until the explicit Stop() lifecycle hook, rather than exiting early
	// when the signal context is cancelled.
	bc.rateLimiter.StartCleanup(context.Background())
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "rate-limiter-stop", Phase: lifecycle.PhaseDrainRequests,
		Timeout: 3 * time.Second,
		Fn:      func(ctx context.Context) error { bc.rateLimiter.Stop(); return nil },
	})

	// Validation (outermost)
	actionValidationInterceptor := action.NewActionValidationInterceptor(preValidation, bc.logger)

	// Single InterceptorChain
	mcpNormalizer := action.NewMCPNormalizer()
	bc.interceptorChain = action.NewInterceptorChain(mcpNormalizer, actionValidationInterceptor, bc.logger)

	return nil
}

// bootRecording sets up session recording (passive observer).
func (bc *bootContext) bootRecording(ctx context.Context, _ action.ActionInterceptor) {
	var recordingCfg recording.RecordingConfig
	if bc.appState.RecordingConfig != nil {
		rc := bc.appState.RecordingConfig
		recordingCfg = recording.RecordingConfig{
			Enabled: rc.Enabled, RecordPayloads: rc.RecordPayloads,
			MaxFileSize: rc.MaxFileSize, RetentionDays: rc.RetentionDays,
			RedactPatterns: rc.RedactPatterns, StorageDir: rc.StorageDir,
			AutoRedactPII: rc.AutoRedactPII,
		}
	} else {
		recordingCfg = recording.DefaultConfig()
	}
	// M-23: Handle absolute StorageDir from state.json gracefully to avoid
	// orphaning recordings at the original path.
	savedAbsDir := ""
	if filepath.IsAbs(recordingCfg.StorageDir) && recordingCfg.StorageDir != "" {
		savedAbsDir = recordingCfg.StorageDir
		bc.logger.Warn("recording: StorageDir is an absolute path; using it to preserve existing recordings",
			"storage_dir", savedAbsDir)
		recordingCfg.StorageDir = recording.DefaultStorageDir // pass validation
	}
	if err := recordingCfg.Validate(); err != nil {
		bc.logger.Warn("recording config invalid, using defaults", "error", err)
		recordingCfg = recording.DefaultConfig()
		savedAbsDir = "" // don't restore invalid config
	}
	if savedAbsDir != "" {
		recordingCfg.StorageDir = savedAbsDir
	} else if !filepath.IsAbs(recordingCfg.StorageDir) {
		recordingCfg.StorageDir = filepath.Join(filepath.Dir(bc.statePath), recordingCfg.StorageDir)
	}

	var fileRecorder *recording.FileRecorder
	var retentionCleaner *recording.RetentionCleaner
	if fr, err := recording.NewFileRecorder(recordingCfg, bc.logger); err != nil {
		bc.logger.Warn("recording: failed to create FileRecorder, recording disabled", "error", err)
	} else {
		fileRecorder = fr
		recSessionAdapter := &recordingSessionAdapter{tracker: bc.sessionTracker}
		bc.recordingObserver = recording.NewRecordingObserver(fileRecorder, recSessionAdapter, bc.logger)
		// Wire quota limits so recording events include configured limits (Bug 6 fix).
		if bc.quotaStore != nil {
			bc.recordingObserver.SetQuotaLimitProvider(&quotaLimitAdapter{store: bc.quotaStore})
		}
		retentionCleaner = recording.NewRetentionCleaner(recordingCfg, bc.logger)
		retentionCleaner.Start(context.Background())

		// Register goroutine cleanup with lifecycle so they stop at shutdown.
		bc.lifecycle.Register(lifecycle.Hook{
			Name: "recording-reaper-stop", Phase: lifecycle.PhaseCloseConnections,
			Timeout: 3 * time.Second,
			Fn:      func(ctx context.Context) error { fileRecorder.StopReaper(); return nil },
		})
		bc.lifecycle.Register(lifecycle.Hook{
			Name: "retention-cleaner-stop", Phase: lifecycle.PhaseCloseConnections,
			Timeout: 3 * time.Second,
			Fn:      func(ctx context.Context) error { retentionCleaner.Stop(); return nil },
		})
		// M-28: Close all active recording sessions at shutdown to sync/close file handles.
		bc.lifecycle.Register(lifecycle.Hook{
			Name: "recording-sessions-close", Phase: lifecycle.PhaseCleanup,
			Timeout: 5 * time.Second,
			Fn:      func(ctx context.Context) error { fileRecorder.CloseAllSessions(); return nil },
		})

		bc.logger.Info("session recording configured",
			"enabled", recordingCfg.Enabled,
			"storage_dir", recordingCfg.StorageDir,
			"retention_days", recordingCfg.RetentionDays,
		)
	}

	bc.apiHandler.SetRecordingService(fileRecorder)
	bc.apiHandler.SetRecordingObserver(bc.recordingObserver)
	bc.apiHandler.SetRetentionCleaner(retentionCleaner)
}

// sessionUsageAdapter bridges session.SessionTracker to action.SessionUsageProvider.
type sessionUsageAdapter struct {
	tracker *session.SessionTracker
}

func (a *sessionUsageAdapter) GetUsage(sessionID string) (action.SessionUsageData, bool) {
	u, ok := a.tracker.GetUsage(sessionID)
	if !ok {
		return action.SessionUsageData{}, false
	}
	data := action.SessionUsageData{
		TotalCalls:     u.TotalCalls,
		ReadCalls:      u.ReadCalls,
		WriteCalls:     u.WriteCalls,
		DeleteCalls:    u.DeleteCalls,
		CumulativeCost: u.CumulativeCost,
		StartedAt:      u.StartedAt,
	}
	// Copy action history
	history, hok := a.tracker.GetActionHistory(sessionID)
	if hok {
		records := make([]action.SessionActionRecord, len(history))
		for i, r := range history {
			records[i] = action.SessionActionRecord{
				ToolName:  r.ToolName,
				CallType:  string(r.CallType),
				Timestamp: r.Timestamp,
				ArgKeys:   r.ArgKeys,
			}
		}
		data.ActionHistory = records
	}
	// Copy action set and arg key set
	if actionSet, aok := a.tracker.GetActionSet(sessionID); aok {
		data.ActionSet = actionSet
	}
	if argKeySet, kok := a.tracker.GetArgKeySet(sessionID); kok {
		data.ArgKeySet = argKeySet
	}
	return data, true
}

// recordingSessionAdapter bridges session.SessionTracker to recording.SessionInfoProvider.
type recordingSessionAdapter struct {
	tracker *session.SessionTracker
}

func (a *recordingSessionAdapter) GetUsage(sessionID string) (recording.SessionUsageSnapshot, bool) {
	u, ok := a.tracker.GetUsage(sessionID)
	if !ok {
		return recording.SessionUsageSnapshot{}, false
	}
	return recording.SessionUsageSnapshot{
		TotalCalls:  u.TotalCalls,
		ReadCalls:   u.ReadCalls,
		WriteCalls:  u.WriteCalls,
		DeleteCalls: u.DeleteCalls,
	}, true
}

// quotaLimitAdapter bridges quota.QuotaStore to recording.QuotaLimitProvider.
type quotaLimitAdapter struct {
	store quota.QuotaStore
}

func (a *quotaLimitAdapter) GetLimits(identityID string) (recording.QuotaLimitsSnapshot, bool) {
	cfg, err := a.store.Get(context.Background(), identityID)
	if err != nil || !cfg.Enabled {
		return recording.QuotaLimitsSnapshot{}, false
	}
	return recording.QuotaLimitsSnapshot{
		MaxCallsPerSession:   cfg.MaxCallsPerSession,
		MaxWritesPerSession:  cfg.MaxWritesPerSession,
		MaxDeletesPerSession: cfg.MaxDeletesPerSession,
		MaxCallsPerMinute:    cfg.MaxCallsPerMinute,
	}, true
}
