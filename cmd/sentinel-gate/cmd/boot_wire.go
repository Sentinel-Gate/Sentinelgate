package cmd

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/admin"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/quota"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/recording"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/storage"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/transform"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/lifecycle"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// bootContext accumulates all components created during the boot sequence.
// Each boot phase is a method that populates fields. The validate() method
// checks that all required components are wired before starting the transport.
//
// This replaces the monolithic run() function that was 800+ lines (A1 decomposition).
type bootContext struct {
	// --- Input ---
	cfg       *config.OSSConfig
	statePath string
	logger    *slog.Logger
	startTime time.Time

	// --- BOOT-03/04: Stores ---
	stateStore    *state.FileStateStore
	appState      *state.AppState
	authStore     *memory.AuthStore
	sessionStore  *memory.MemorySessionStore
	policyStore   *memory.MemoryPolicyStore
	upstreamStore *memory.MemoryUpstreamStore
	rateLimiter   *memory.MemoryRateLimiter

	// --- Services ---
	apiKeyService      *auth.APIKeyService
	sessionService     *session.SessionService
	policyService      *service.PolicyService
	policyEvalService  *service.PolicyEvaluationService
	policyAdminService *service.PolicyAdminService
	auditService       *service.AuditService
	auditStore         *memory.MemoryAuditStore
	statsService       *service.StatsService
	identityService    *service.IdentityService
	templateService    *service.TemplateService
	upstreamService    *service.UpstreamService

	// --- Event Bus (A4) ---
	eventBus *event.InProcessBus

	// --- Notifications (UX-F3) ---
	notificationService *service.NotificationService

	// --- Storage (A5) ---
	timeSeriesStore storage.TimeSeriesStore
	versionedStore  storage.VersionedStore

	// --- Evidence (Upgrade 1) ---
	evidenceService *service.EvidenceService

	// --- Compliance (Upgrade 2) ---
	complianceService *service.ComplianceService

	// --- Simulation (UX-F1) ---
	simulationService *service.SimulationService

	// --- Drift Detection (Upgrade 5) ---
	driftService *service.DriftService

	// --- Permission Health (Upgrade 6) ---
	permissionHealthService *service.PermissionHealthService
	toolCacheAdapter        *toolCacheToolLister
	identityListAdapter     *stateIdentityLister

	// --- Namespace Isolation (Upgrade 8) ---
	namespaceService *service.NamespaceService

	// --- Telemetry (Upgrade 9) ---
	telemetryService *service.TelemetryService

	// --- Red Team Testing (Upgrade 10) ---
	redteamService *service.RedTeamService

	// --- FinOps (Upgrade 12) ---
	finopsService *service.FinOpsService

	// --- Health Dashboard (Upgrade 11) ---
	healthService           *service.HealthService
	policyActionInterceptor *action.PolicyActionInterceptor

	// --- Webhook ---
	webhookService *service.WebhookService

	// --- BOOT-05/06: Upstreams ---
	upstreamManager     *service.UpstreamManager
	discoveryService    *service.ToolDiscoveryService
	toolCache           *upstream.ToolCache
	toolSecurityService *service.ToolSecurityService
	connectedCount      int
	statusAll           map[string]upstream.ConnectionStatus
	toolCount           int

	// --- Admin API ---
	apiHandler *admin.AdminAPIHandler

	// --- BOOT-07: Interceptor chain ---
	interceptorChain        proxy.MessageInterceptor
	upstreamRouter          *proxy.UpstreamRouter
	actionAuthInterceptor   *action.ActionAuthInterceptor
	sessionTracker          *session.SessionTracker
	responseScanner         *action.ResponseScanner
	responseScanInterceptor *action.ResponseScanInterceptor
	contentScanner          *action.ContentScanner
	contentScanInterceptor  *action.ContentScanInterceptor
	approvalStore           *action.ApprovalStore
	transformStore          *transform.MemoryTransformStore
	transformExecutor       *transform.TransformExecutor
	quotaStore              *quota.MemoryQuotaStore
	recordingObserver       *recording.RecordingObserver

	// --- Transport ---
	mcpClient    outbound.MCPClient
	proxyService *service.ProxyService

	// --- Lifecycle (A6) ---
	lifecycle *lifecycle.Manager

	// --- Cleanup (legacy, used alongside lifecycle) ---
	cleanups []func()
}

// runCleanups executes all registered cleanup functions in reverse order.
func (bc *bootContext) runCleanups() {
	for i := len(bc.cleanups) - 1; i >= 0; i-- {
		bc.cleanups[i]()
	}
}

// validate checks that all critical components are wired. Fail fast with
// a clear message instead of nil pointer panic at runtime.
func (bc *bootContext) validate() error {
	checks := []struct {
		name string
		ok   bool
	}{
		{"state_store", bc.stateStore != nil},
		{"auth_store", bc.authStore != nil},
		{"session_store", bc.sessionStore != nil},
		{"policy_store", bc.policyStore != nil},
		{"api_key_service", bc.apiKeyService != nil},
		{"session_service", bc.sessionService != nil},
		{"policy_service", bc.policyService != nil},
		{"audit_service", bc.auditService != nil},
		{"upstream_service", bc.upstreamService != nil},
		{"upstream_manager", bc.upstreamManager != nil},
		{"tool_cache", bc.toolCache != nil},
		{"interceptor_chain", bc.interceptorChain != nil},
		{"rate_limiter", bc.rateLimiter != nil},
		{"event_bus", bc.eventBus != nil},
		{"audit_store", bc.auditStore != nil},
		{"stats_service", bc.statsService != nil},
		{"admin_api_handler", bc.apiHandler != nil},
	}

	for _, c := range checks {
		if !c.ok {
			return fmt.Errorf("boot validation failed: %s not initialized", c.name)
		}
	}

	bc.logger.Debug("boot validation passed", "components", len(checks))
	return nil
}
