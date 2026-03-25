package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/admin"
	evidenceAdapter "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/evidence"
	storageAdapter "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/storage"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	ev "github.com/Sentinel-Gate/Sentinelgate/internal/domain/evidence"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/lifecycle"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// bootServices creates all domain services from stores (services layer).
func (bc *bootContext) bootServices(ctx context.Context) error {
	// Parse session timeout
	sessionTimeout, err := time.ParseDuration(bc.cfg.Server.SessionTimeout)
	if err != nil {
		sessionTimeout = 30 * time.Minute
		bc.logger.Warn("invalid session_timeout, using default",
			"value", bc.cfg.Server.SessionTimeout, "default", "30m")
	}

	bc.apiKeyService = auth.NewAPIKeyService(bc.authStore)
	bc.sessionService = session.NewSessionService(bc.sessionStore, session.Config{
		Timeout: sessionTimeout,
	})
	bc.policyService, err = service.NewPolicyService(ctx, bc.policyStore, bc.logger)
	if err != nil {
		return fmt.Errorf("failed to create policy service: %w", err)
	}

	bc.policyEvalService = service.NewPolicyEvaluationService(bc.policyService, bc.policyStore, bc.stateStore, bc.logger)
	// H-10: Restore persisted pending evaluations (approval_required, etc.) from state.json.
	bc.policyEvalService.LoadFromState(bc.appState)

	// Audit store + service
	bc.auditStore, err = createAuditStore(bc.cfg, bc.logger)
	if err != nil {
		return fmt.Errorf("failed to create audit store: %w", err)
	}
	// M-41: Only register via lifecycle hook (not addCleanup) to avoid double-close.
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "audit-store-close", Phase: lifecycle.PhaseCleanup,
		Timeout: 3 * time.Second,
		Fn:      func(ctx context.Context) error { return bc.auditStore.Close() },
	})

	flushInterval, err := time.ParseDuration(bc.cfg.Audit.FlushInterval)
	if err != nil {
		flushInterval = time.Second
		bc.logger.Warn("invalid flush_interval, using default", "value", bc.cfg.Audit.FlushInterval, "default", "1s")
	}
	sendTimeout, err := time.ParseDuration(bc.cfg.Audit.SendTimeout)
	if err != nil {
		sendTimeout = 100 * time.Millisecond
		bc.logger.Warn("invalid send_timeout, using default", "value", bc.cfg.Audit.SendTimeout, "default", "100ms")
	}

	bc.auditService = service.NewAuditService(bc.auditStore, bc.logger,
		service.WithChannelSize(bc.cfg.Audit.ChannelSize),
		service.WithBatchSize(bc.cfg.Audit.BatchSize),
		service.WithFlushInterval(flushInterval),
		service.WithSendTimeout(sendTimeout),
		service.WithWarningThreshold(bc.cfg.Audit.WarningThreshold),
	)
	bc.auditService.Start(context.Background())

	// Register lifecycle hooks (A6: ordered shutdown)
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "audit-flush", Phase: lifecycle.PhaseFlushBuffers,
		Timeout: 5 * time.Second,
		Fn:      func(ctx context.Context) error { bc.auditService.Stop(); return nil },
	})

	// Event Bus (A4: Internal Event Bus)
	bc.eventBus = event.NewBus(1000)
	bc.eventBus.Start()

	// Notification Center (UX-F3: subscribes to all events)
	bc.notificationService = service.NewNotificationService(500)
	bc.notificationService.SubscribeToBus(bc.eventBus)
	// Unsubscribe BEFORE the event bus is drained (both in PhaseFlushBuffers,
	// but notification-stop sorts first because hooks in the same phase run
	// in registration order and this is registered before event-bus-drain).
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "notification-stop", Phase: lifecycle.PhaseFlushBuffers,
		Timeout: 3 * time.Second,
		Fn:      func(ctx context.Context) error { bc.notificationService.Stop(); return nil },
	})

	// Storage abstraction (A5: TimeSeriesStore + VersionedStore)
	if err := bc.bootStorage(ctx); err != nil {
		return fmt.Errorf("boot storage: %w", err)
	}

	// Evidence service (Upgrade 1: Cryptographic Evidence)
	// Honor state.json override: same override-when-present pattern as other toggles.
	if bc.evidenceEnabled() {
		keyPath := bc.cfg.Evidence.KeyPath
		if keyPath == "" {
			keyPath = "evidence-key.pem"
		}
		signerID := bc.cfg.Evidence.SignerID
		if signerID == "" {
			signerID, _ = os.Hostname()
			if signerID == "" {
				signerID = "sentinel-gate"
			}
		}

		signer, signerErr := evidenceAdapter.NewECDSASigner(keyPath, signerID)
		if signerErr != nil {
			return fmt.Errorf("failed to create evidence signer: %w", signerErr)
		}

		// Use VersionedStore for evidence if available, otherwise fall back to JSONL file.
		// In both cases, evidence is also written to a flat JSONL file so the CLI
		// "sentinel-gate verify" command can verify the chain.
		var evStore service.EvidenceStore
		var chainPersister service.ChainStatePersister
		var jsonlStore *evidenceAdapter.FileStore

		outputPath := bc.cfg.Evidence.OutputPath
		if outputPath == "" {
			outputPath = "evidence.jsonl"
		}

		if bc.versionedStore != nil {
			ves := storageAdapter.NewVersionedEvidenceStore(bc.versionedStore)
			chainPersister = ves // VersionedEvidenceStore implements ChainStatePersister

			// Dual-write: also append to JSONL flat file for CLI verification.
			fs, storeErr := evidenceAdapter.NewFileStore(outputPath)
			if storeErr != nil {
				return fmt.Errorf("failed to create evidence JSONL store: %w", storeErr)
			}
			jsonlStore = fs
			evStore = &dualEvidenceStore{primary: ves, secondary: fs, logger: bc.logger}
			bc.logger.Info("evidence using versioned store + JSONL dual-write", "jsonl_path", outputPath)
		} else {
			fs, storeErr := evidenceAdapter.NewFileStore(outputPath)
			if storeErr != nil {
				return fmt.Errorf("failed to create evidence store: %w", storeErr)
			}
			jsonlStore = fs
			evStore = fs
			// FileStore has no chain state persistence; chain restarts from genesis.
		}

		bc.evidenceService = service.NewEvidenceService(signer, evStore, bc.logger, chainPersister)

		// Boot-time chain verification (best-effort, non-blocking).
		if jsonlStore != nil {
			pubPEM := signer.PublicKeyPEM()
			if len(pubPEM) > 0 {
				result, verifyErr := evidenceAdapter.VerifyFileWithPubKey(jsonlStore.Path(), pubPEM)
				if verifyErr != nil {
					bc.logger.Warn("evidence: chain verification failed at boot", "error", verifyErr)
				} else if result.TotalRecords > 0 {
					if result.InvalidSigs > 0 || !result.ChainValid {
						bc.logger.Warn("evidence: CHAIN INTEGRITY ISSUE DETECTED",
							"total_records", result.TotalRecords,
							"invalid_sigs", result.InvalidSigs,
							"chain_valid", result.ChainValid,
							"first_error", result.FirstError)
					} else {
						bc.logger.Info("evidence: chain verified at boot",
							"records", result.TotalRecords, "all_valid", true)
					}
				}
			}
		}

		bc.lifecycle.Register(lifecycle.Hook{
			Name: "evidence-close", Phase: lifecycle.PhaseCleanup,
			Timeout: 3 * time.Second,
			Fn:      func(ctx context.Context) error { return bc.evidenceService.Close() },
		})

		bc.logger.Info("evidence signing enabled",
			"key", keyPath, "signer", signerID)
	}

	// Policy admin + identity + templates + stats
	bc.policyAdminService = service.NewPolicyAdminService(bc.policyStore, bc.stateStore, bc.policyService, bc.logger)
	if err := bc.policyAdminService.LoadPoliciesFromState(ctx, bc.appState); err != nil {
		bc.logger.Error("failed to load policies from state", "error", err)
	}

	bc.identityService = service.NewIdentityService(bc.stateStore, bc.logger)
	if err := bc.identityService.Init(); err != nil {
		return fmt.Errorf("init identity service: %w", err)
	}
	bc.identityService.SetPostMutationHook(func() {
		hookState, loadErr := bc.stateStore.Load()
		if loadErr != nil {
			bc.logger.Error("PostMutationHook: failed to load state for auth re-seed", "error", loadErr)
			return
		}
		// M-11: Pass cfg so seedAuthFromState can distinguish YAML-seeded
		// entries from state-sourced ones and remove revoked/deleted keys.
		seedAuthFromState(hookState, bc.authStore, bc.cfg, bc.logger)
	})
	// H-1: Invalidate cached sessions when identity roles change.
	bc.identityService.SetSessionInvalidator(func(identityID string) {
		if bc.actionAuthInterceptor != nil {
			bc.actionAuthInterceptor.InvalidateByIdentity(identityID)
		}
	})

	bc.templateService = service.NewTemplateService(bc.policyAdminService, bc.logger)
	bc.statsService = service.NewStatsService()

	// Namespace isolation (Upgrade 8): config from state.json.
	bc.namespaceService = service.NewNamespaceService(bc.logger)
	if bc.appState.NamespaceConfig != nil {
		cfg := service.NamespaceConfig{
			Enabled: bc.appState.NamespaceConfig.Enabled,
			Rules:   make(map[string]*service.NamespaceRule),
		}
		for role, rule := range bc.appState.NamespaceConfig.Rules {
			cfg.Rules[role] = &service.NamespaceRule{
				VisibleTools: rule.VisibleTools,
				HiddenTools:  rule.HiddenTools,
			}
		}
		bc.namespaceService.SetConfig(cfg)
		if cfg.Enabled {
			bc.logger.Info("namespace isolation enabled", "rules", len(cfg.Rules))
		}
	}

	return nil
}

// bootComplianceAndSimulation wires Compliance (Upgrade 2) and Simulation (UX-F1)
// services. Called after bootAdminAPI + bootInterceptorChain since it references
// apiHandler, interceptor, and approval store fields.
func (bc *bootContext) bootComplianceAndSimulation() {
	// Compliance service
	complianceReader := func(n int) []service.AuditRecordCompat {
		recent := bc.auditStore.GetRecent(n)
		result := make([]service.AuditRecordCompat, len(recent))
		for i, r := range recent {
			result[i] = service.AuditRecordCompat{
				Timestamp:      r.Timestamp,
				Decision:       r.Decision,
				Reason:         r.Reason,
				ToolName:       r.ToolName,
				IdentityID:     r.IdentityID,
				IdentityName:   r.IdentityName,
				SessionID:      r.SessionID,
				ToolArguments:  r.ToolArguments,
				ScanDetections: r.ScanDetections,
				ScanTypes:      r.ScanTypes,
			}
		}
		return result
	}
	bc.complianceService = service.NewComplianceService(complianceReader, bc.logger)
	bc.apiHandler.SetComplianceService(bc.complianceService)
	bc.apiHandler.SetComplianceContextProvider(func() service.ComplianceContext {
		// Read live counts from services, not the stale boot-time appState snapshot.
		// appState is loaded once at boot and never updated when identities/policies
		// are created via the admin API.
		identityCount := 0
		apiKeyCount := 0
		if bc.identityService != nil {
			if ids, err := bc.identityService.ListIdentities(context.Background()); err == nil {
				identityCount = len(ids)
			}
			if keys, err := bc.identityService.ListAllKeys(context.Background()); err == nil {
				apiKeyCount = len(keys)
			}
		}

		policyCount := 0
		denyRuleCount := 0
		if bc.policyAdminService != nil {
			if policies, err := bc.policyAdminService.List(context.Background()); err == nil {
				policyCount = len(policies)
				for _, p := range policies {
					for _, r := range p.Rules {
						if r.Action == policy.ActionDeny || r.Action == policy.ActionApprovalRequired {
							denyRuleCount++
						}
					}
				}
			}
		}

		return service.ComplianceContext{
			EvidenceEnabled:     bc.evidenceEnabled(),
			ContentScanEnabled:  bc.responseScanInterceptor != nil && bc.responseScanInterceptor.Enabled(),
			InputScanEnabled:    bc.contentScanInterceptor != nil && bc.contentScanInterceptor.Enabled(),
			ToolIntegrityActive: bc.toolSecurityService != nil && len(bc.toolSecurityService.GetBaseline()) > 0,
			RateLimitEnabled:    bc.cfg.RateLimit.Enabled,
			IdentityCount:       identityCount,
			PolicyCount:         policyCount,
			APIKeyCount:         apiKeyCount,
			DenyRuleCount:       denyRuleCount,
			HITLAvailable:       bc.approvalStore != nil,
		}
	})

	// Simulation service
	simReader := func(n int) []audit.AuditRecord {
		return bc.auditStore.GetRecent(n)
	}
	bc.simulationService = service.NewSimulationService(bc.policyService, simReader, bc.logger)
	bc.apiHandler.SetSimulationService(bc.simulationService)

	bc.logger.Info("compliance and simulation services wired")

	// Drift Detection (Upgrade 5)
	bc.driftService = service.NewDriftService(bc.auditStore, bc.timeSeriesStore, bc.logger)
	if bc.eventBus != nil {
		bc.driftService.SetEventBus(bc.eventBus)
	}
	// H-8: Load persisted drift config from state.json.
	// M-25: Trust stored values (including zeros) — zero may be intentional
	// (e.g., disabling a threshold check). Only use defaults for window days
	// which must be positive to function.
	if bc.appState.DriftConfig != nil {
		dc := bc.appState.DriftConfig
		cfg := service.DriftConfig{
			BaselineWindowDays: dc.BaselineWindowDays,
			CurrentWindowDays:  dc.CurrentWindowDays,
			ToolShiftThreshold: dc.ToolShiftThreshold,
			DenyRateThreshold:  dc.DenyRateThreshold,
			ErrorRateThreshold: dc.ErrorRateThreshold,
			LatencyThreshold:   dc.LatencyThreshold,
			TemporalThreshold:  dc.TemporalThreshold,
			ArgShiftThreshold:  dc.ArgShiftThreshold,
			MinCallsBaseline:   dc.MinCallsBaseline,
		}
		defaults := service.DefaultDriftConfig()
		if cfg.BaselineWindowDays == 0 { cfg.BaselineWindowDays = defaults.BaselineWindowDays }
		if cfg.CurrentWindowDays == 0 { cfg.CurrentWindowDays = defaults.CurrentWindowDays }
		if cfg.MinCallsBaseline == 0 { cfg.MinCallsBaseline = defaults.MinCallsBaseline }
		bc.driftService.SetConfig(cfg)
		bc.logger.Info("loaded drift config from state", "baseline_days", cfg.BaselineWindowDays)
	}
	bc.apiHandler.SetDriftService(bc.driftService)
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "drift-service-stop", Phase: lifecycle.PhaseCleanup,
		Timeout: 3 * time.Second,
		Fn:      func(ctx context.Context) error { bc.driftService.Stop(); return nil },
	})
	bc.logger.Info("drift detection service wired")

	// Permission Health / Shadow Mode (Upgrade 6)
	bc.toolCacheAdapter = &toolCacheToolLister{cache: bc.toolCache}
	bc.identityListAdapter = &stateIdentityLister{stateStore: bc.stateStore, authStore: bc.authStore}
	bc.permissionHealthService = service.NewPermissionHealthService(
		bc.auditStore,
		bc.toolCacheAdapter,
		bc.identityListAdapter,
		bc.policyService,
		bc.logger,
	)
	bc.permissionHealthService.SetDriftService(bc.driftService)
	if bc.eventBus != nil {
		bc.permissionHealthService.SetEventBus(bc.eventBus)
	}
	if bc.timeSeriesStore != nil {
		bc.permissionHealthService.SetTimeSeriesStore(bc.timeSeriesStore)
	}
	// H-7: Load persisted permission health config from state.json.
	if bc.appState.PermissionHealthConfig != nil {
		// M-27: Validate mode against known values; fall back to "disabled" on invalid.
		mode := service.ShadowMode(bc.appState.PermissionHealthConfig.Mode)
		switch mode {
		case service.ShadowModeDisabled, service.ShadowModeShadow, service.ShadowModeSuggest, service.ShadowModeAuto:
			// valid
		default:
			bc.logger.Warn("invalid permission health mode in state, defaulting to disabled", "mode", bc.appState.PermissionHealthConfig.Mode)
			mode = service.ShadowModeDisabled
		}
		bc.permissionHealthService.SetConfig(service.PermissionHealthConfig{
			Mode:            mode,
			LearningDays:    bc.appState.PermissionHealthConfig.LearningDays,
			GracePeriodDays: bc.appState.PermissionHealthConfig.GracePeriodDays,
			WhitelistTools:  bc.appState.PermissionHealthConfig.WhitelistTools,
			UpdatedAt:       bc.appState.PermissionHealthConfig.UpdatedAt,
		})
		bc.logger.Info("loaded permission health config from state",
			"mode", bc.appState.PermissionHealthConfig.Mode)
	}
	bc.apiHandler.SetPermissionHealthService(bc.permissionHealthService)
	bc.apiHandler.SetNamespaceService(bc.namespaceService)
	bc.logger.Info("permission health service wired")

	// Telemetry / OpenTelemetry stdout export (Upgrade 9)
	// Config loaded from state.json (runtime, managed via admin UI).
	telemetryCfg := service.DefaultTelemetryConfig()
	if bc.appState.TelemetryConfig != nil {
		telemetryCfg.Enabled = bc.appState.TelemetryConfig.Enabled
		if bc.appState.TelemetryConfig.ServiceName != "" {
			telemetryCfg.ServiceName = bc.appState.TelemetryConfig.ServiceName
		}
	}
	var telErr error
	bc.telemetryService, telErr = service.NewTelemetryService(telemetryCfg, bc.logger)
	if telErr != nil {
		bc.logger.Error("failed to create telemetry service", "error", telErr)
	} else {
		if bc.eventBus != nil {
			bc.telemetryService.SubscribeToBus(bc.eventBus)
		}
		bc.apiHandler.SetTelemetryService(bc.telemetryService)
		if telemetryCfg.Enabled {
			bc.logger.Info("telemetry stdout export enabled", "service", telemetryCfg.ServiceName)
		}
	}

	// Red Team Testing (Upgrade 10)
	bc.redteamService = service.NewRedTeamService(bc.policyService, bc.logger)
	if bc.eventBus != nil {
		bc.redteamService.SetEventBus(bc.eventBus)
	}
	if bc.contentScanInterceptor != nil && bc.contentScanner != nil {
		scanner := bc.contentScanner
		bc.redteamService.SetContentScanFn(func(args map[string]interface{}) (detected, blocked bool) {
			result := scanner.ScanArguments(args)
			return result.Detected, result.HasBlock
		})
	}
	bc.apiHandler.SetRedTeamService(bc.redteamService)
	bc.logger.Info("red team testing service wired")

	// FinOps Cost Explorer (Upgrade 12)
	bc.finopsService = service.NewFinOpsService(bc.auditStore, bc.logger)
	if bc.eventBus != nil {
		bc.finopsService.SetEventBus(bc.eventBus)
	}
	if bc.appState.FinOpsConfig != nil {
		defaults := service.DefaultFinOpsConfig()
		fc := bc.appState.FinOpsConfig
		cfg := service.FinOpsConfig{
			Enabled:            fc.Enabled,
			DefaultCostPerCall: fc.DefaultCostPerCall,
			ToolCosts:          fc.ToolCosts,
			Budgets:            fc.Budgets,
			BudgetActions:      fc.BudgetActions,
			AlertThresholds:    fc.AlertThresholds,
		}
		// M-26: Trust stored DefaultCostPerCall (zero = free tier, intentional).
		// Only default AlertThresholds if empty (structural, not numeric).
		if len(cfg.AlertThresholds) == 0 { cfg.AlertThresholds = defaults.AlertThresholds }
		// Initialize nil maps to prevent panics on write (old state.json may lack these).
		if cfg.ToolCosts == nil { cfg.ToolCosts = make(map[string]float64) }
		if cfg.Budgets == nil { cfg.Budgets = make(map[string]float64) }
		if cfg.BudgetActions == nil { cfg.BudgetActions = make(map[string]string) }
		// L-45: Validate config loaded from state.json before runtime use.
		admin.SanitizeFinOpsStateConfig(&cfg, bc.logger)
		bc.finopsService.SetConfig(cfg)
	}
	bc.apiHandler.SetFinOpsService(bc.finopsService)
	bc.logger.Info("finops cost explorer service wired")

	// Agent Health Dashboard (Upgrade 11)
	bc.healthService = service.NewHealthService(bc.auditStore, bc.logger)
	bc.healthService.SetDriftService(bc.driftService)
	if bc.eventBus != nil {
		bc.healthService.SetEventBus(bc.eventBus)
	}
	if bc.timeSeriesStore != nil {
		bc.healthService.SetTimeSeriesStore(bc.timeSeriesStore)
	}
	if bc.appState.HealthConfig != nil {
		// M-15: When HealthConfig is present in state.json, use the stored
		// values directly without zero-value fallback. The HealthConfigEntry
		// fields do not use omitempty, so 0.0 is a valid intentional value
		// (e.g. to disable a specific threshold check). Falling back to
		// defaults on zero would silently overwrite admin intent on restart.
		hc := bc.appState.HealthConfig
		bc.healthService.SetConfig(service.HealthConfig{
			DenyRateWarning:    hc.DenyRateWarning,
			DenyRateCritical:   hc.DenyRateCritical,
			DriftScoreWarning:  hc.DriftScoreWarning,
			DriftScoreCritical: hc.DriftScoreCritical,
			ErrorRateWarning:   hc.ErrorRateWarning,
			ErrorRateCritical:  hc.ErrorRateCritical,
		})
	}
	bc.apiHandler.SetHealthService(bc.healthService)
	// Late-bind health metrics to policy interceptor for CEL variables
	if bc.policyActionInterceptor != nil {
		bc.policyActionInterceptor.SetHealthMetrics(&healthMetricsAdapter{svc: bc.healthService})
	}
	bc.logger.Info("agent health dashboard service wired")

	// Webhook notifications (M-29: validate URL to prevent SSRF)
	if bc.cfg.Webhook.URL != "" && bc.eventBus != nil {
		if msg := validateWebhookURL(bc.cfg.Webhook.URL); msg != "" {
			bc.logger.Error("webhook URL rejected, webhook disabled",
				"url", bc.cfg.Webhook.URL, "reason", msg)
		} else if s := bc.cfg.Webhook.Secret; s != "" && len(s) < 32 {
			// M-32: Reject webhook secret shorter than 32 chars to ensure HMAC strength.
			bc.logger.Error("webhook secret too short, webhook disabled",
				"length", len(s), "minimum", 32)
		} else {
			bc.webhookService = service.NewWebhookService(
				bc.cfg.Webhook.URL, bc.cfg.Webhook.Secret,
				bc.cfg.Webhook.Events, bc.logger,
			)
			bc.webhookService.SubscribeToBus(bc.eventBus)
			// Stop webhook before event bus drain so in-flight deliveries complete
			// while the transport is still open.
			bc.lifecycle.Register(lifecycle.Hook{
				Name: "webhook-stop", Phase: lifecycle.PhaseFlushBuffers,
				Timeout: 5 * time.Second,
				Fn:      func(ctx context.Context) error { bc.webhookService.Stop(); return nil },
			})
			bc.logger.Info("webhook notifications enabled", "url", bc.cfg.Webhook.URL, "events", len(bc.cfg.Webhook.Events))
		}
	}

	bc.lifecycle.Register(lifecycle.Hook{
		Name: "event-bus-drain", Phase: lifecycle.PhaseFlushBuffers,
		Timeout: 3 * time.Second,
		Fn:      func(ctx context.Context) error { bc.eventBus.Stop(); return nil },
	})

	// L-16: Register telemetry-shutdown AFTER event-bus-drain so the bus delivers
	// remaining events to telemetry before telemetry shuts down. Within the same
	// phase, hooks run in registration order.
	if bc.telemetryService != nil {
		bc.lifecycle.Register(lifecycle.Hook{
			Name: "telemetry-shutdown", Phase: lifecycle.PhaseFlushBuffers,
			Timeout: 5 * time.Second,
			Fn:      func(ctx context.Context) error { return bc.telemetryService.Shutdown(ctx) },
		})
	}
}

// healthMetricsAdapter adapts service.HealthService to action.HealthMetricsProvider.
type healthMetricsAdapter struct {
	svc *service.HealthService
}

func (a *healthMetricsAdapter) GetHealthMetrics(ctx context.Context, identityID string) action.HealthMetricsData {
	m := a.svc.GetMetricsForCEL(ctx, identityID)
	return action.HealthMetricsData{
		DenyRate:       m.DenyRate,
		DriftScore:     m.DriftScore,
		ViolationCount: m.ViolationCount,
		TotalCalls:     m.TotalCalls,
		ErrorRate:      m.ErrorRate,
	}
}

// dualEvidenceStore writes every evidence record to both primary (versioned)
// and secondary (JSONL flat file) stores. Primary errors are propagated;
// secondary errors are logged but non-blocking.
type dualEvidenceStore struct {
	primary   service.EvidenceStore
	secondary service.EvidenceStore
	logger    *slog.Logger
}

func (d *dualEvidenceStore) Append(record ev.Record) error {
	if err := d.primary.Append(record); err != nil {
		return err
	}
	if err := d.secondary.Append(record); err != nil {
		d.logger.Warn("evidence: JSONL secondary write failed", "error", err, "record_id", record.ID)
	}
	return nil
}

func (d *dualEvidenceStore) Close() error {
	return errors.Join(d.primary.Close(), d.secondary.Close())
}

// evidenceEnabled returns true when cryptographic evidence should be active.
// When state.json has an EvidenceConfig entry, its Enabled value overrides the
// config default (override-when-present pattern, consistent with other toggles).
func (bc *bootContext) evidenceEnabled() bool {
	if bc.appState.EvidenceConfig != nil {
		return bc.appState.EvidenceConfig.Enabled
	}
	return bc.cfg.Evidence.Enabled
}

// validateWebhookURL checks that a webhook URL is safe (http/https scheme,
// no cloud metadata endpoints). Returns empty string if valid.
// H-2: Resolves hostnames to check all IPs against blocklist.
func validateWebhookURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "invalid URL"
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "only http:// and https:// schemes are allowed"
	}
	if parsed.Host == "" {
		return "URL must include a host"
	}
	hostname := parsed.Hostname()
	ip := net.ParseIP(hostname)
	if ip != nil {
		if msg := isBlockedWebhookIP(ip); msg != "" {
			return msg
		}
	} else {
		// H-2: Resolve hostname and check all IPs.
		addrs, resolveErr := net.DefaultResolver.LookupIPAddr(context.Background(), hostname)
		if resolveErr != nil {
			return fmt.Sprintf("DNS resolution failed for %s: %v", hostname, resolveErr)
		}
		if len(addrs) == 0 {
			return fmt.Sprintf("hostname %s resolved to no addresses", hostname)
		}
		for _, addr := range addrs {
			if msg := isBlockedWebhookIP(addr.IP); msg != "" {
				return fmt.Sprintf("%s (resolved from %s)", msg, hostname)
			}
		}
	}
	return ""
}

// isBlockedWebhookIP checks if an IP should be blocked for webhook SSRF protection.
func isBlockedWebhookIP(ip net.IP) string {
	if ip.IsLoopback() {
		return "loopback IP addresses are not allowed"
	}
	if ip.IsPrivate() {
		return "private IP addresses are not allowed"
	}
	if ip.IsUnspecified() {
		return "unspecified IP addresses (0.0.0.0/::) are not allowed"
	}
	if ip.IsLinkLocalUnicast() {
		return "link-local IP addresses are not allowed (cloud metadata protection)"
	}
	return ""
}
