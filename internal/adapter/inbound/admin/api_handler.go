// Package admin provides web UI and JSON API handlers for Sentinel Gate.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/quota"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/recording"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/transform"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// AuditReader provides read access to recent audit records for the admin API.
// This is a minimal interface used by the admin API; full query support is in audit.AuditQueryStore.
type AuditReader interface {
	// GetRecent returns the N most recent audit records.
	GetRecent(n int) []audit.AuditRecord
	// Query retrieves audit records matching the filter.
	Query(ctx context.Context, filter audit.AuditFilter) ([]audit.AuditRecord, string, error)
}

// SessionCacheInvalidator provides methods to invalidate cached sessions
// in the auth interceptor. BUG-6 FIX: Used by Terminate/Revoke/Delete handlers
// to ensure agents are immediately disconnected.
type SessionCacheInvalidator interface {
	InvalidateBySessionID(sessionID string)
	InvalidateByIdentity(identityID string)
}

// AdminAPIHandler provides JSON API endpoints for the admin interface.
// It coexists with the legacy AdminHandler which serves the template-based UI.
type AdminAPIHandler struct {
	upstreamService         *service.UpstreamService
	upstreamManager         *service.UpstreamManager
	discoveryService        *service.ToolDiscoveryService
	toolCache               *upstream.ToolCache
	policyService           *service.PolicyService
	policyStore             policy.PolicyStore
	auditService            *service.AuditService
	auditReader             AuditReader
	statsService            *service.StatsService
	identityService         *service.IdentityService
	policyEvalService       *service.PolicyEvaluationService
	policyAdminService      *service.PolicyAdminService
	stateStore              *state.FileStateStore
	approvalStore           *action.ApprovalStore
	responseScanCtrl        ResponseScanController
	additionalScanCtrls     []ResponseScanController
	toolSecurityService     *service.ToolSecurityService
	templateService         *service.TemplateService
	quotaStore              quota.QuotaStore
	sessionTracker          *session.SessionTracker
	transformStore          transform.TransformStore
	transformExecutor       *transform.TransformExecutor
	recordingService        *recording.FileRecorder
	recordingObserver       *recording.RecordingObserver
	retentionCleaner        *recording.RetentionCleaner
	notificationService     *service.NotificationService
	contentScanInterceptor  *action.ContentScanInterceptor
	complianceService       *service.ComplianceService
	complianceCtxFn         func() service.ComplianceContext
	simulationService       *service.SimulationService
	driftService            *service.DriftService
	permissionHealthService *service.PermissionHealthService
	telemetryService        *service.TelemetryService
	namespaceService        *service.NamespaceService
	redteamService          *service.RedTeamService
	finopsService           *service.FinOpsService
	healthService           *service.HealthService
	sessionCacheInvalidator SessionCacheInvalidator
	sessionService          *session.SessionService
	eventBus                event.Bus
	buildInfo               *BuildInfo
	logger                  *slog.Logger
	startTime               time.Time
	toolChangeNotifier      service.ToolChangeNotifier
	// trustedProxies holds CIDR ranges of reverse proxies whose X-Forwarded-For
	// header is trusted for client IP resolution (HARD-11). Empty by default.
	trustedProxies []*net.IPNet
	// pendingProxyCIDRs stores raw CIDR strings from WithTrustedProxies until
	// all options are applied, so that parsing/logging uses the final logger.
	pendingProxyCIDRs []string
}

// AdminAPIOption configures an AdminAPIHandler dependency.
type AdminAPIOption func(*AdminAPIHandler)

// WithUpstreamService sets the upstream CRUD service.
func WithUpstreamService(s *service.UpstreamService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.upstreamService = s }
}

// WithUpstreamManager sets the upstream connection lifecycle manager.
func WithUpstreamManager(m *service.UpstreamManager) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.upstreamManager = m }
}

// WithDiscoveryService sets the tool discovery service.
func WithDiscoveryService(s *service.ToolDiscoveryService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.discoveryService = s }
}

// WithToolCache sets the shared tool cache.
func WithToolCache(c *upstream.ToolCache) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.toolCache = c }
}

// WithPolicyService sets the policy evaluation service.
func WithPolicyService(s *service.PolicyService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.policyService = s }
}

// WithPolicyStore sets the policy persistence store.
func WithPolicyStore(s policy.PolicyStore) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.policyStore = s }
}

// WithAuditService sets the audit logging service.
func WithAuditService(s *service.AuditService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.auditService = s }
}

// WithAuditReader sets the audit record reader for queries.
func WithAuditReader(r AuditReader) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.auditReader = r }
}

// WithStateStore sets the file state store.
func WithStateStore(s *state.FileStateStore) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.stateStore = s }
}

// WithAPILogger sets the logger.
func WithAPILogger(l *slog.Logger) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.logger = l }
}

// WithStatsService sets the stats service for dashboard statistics.
func WithStatsService(s *service.StatsService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.statsService = s }
}

// WithBuildInfo sets the build version information.
func WithBuildInfo(info *BuildInfo) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.buildInfo = info }
}

// WithTrustedProxies sets the CIDR ranges of reverse proxies whose X-Forwarded-For header
// is trusted for real client IP resolution (HARD-11). Only requests arriving from these
// ranges will have their X-Forwarded-For header honoured. Invalid CIDRs are skipped with
// a warning log. Default is empty (no proxies trusted, XFF ignored — backward compatible).
//
// CIDR parsing and warning logs are deferred until after all options are applied (CONCERN-01),
// ensuring the configured logger is used regardless of option ordering.
func WithTrustedProxies(cidrs []string) AdminAPIOption {
	return func(h *AdminAPIHandler) {
		h.pendingProxyCIDRs = cidrs
	}
}

// WithToolChangeNotifier sets the notifier for tool list changes.
func WithToolChangeNotifier(n service.ToolChangeNotifier) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.toolChangeNotifier = n }
}

// WithStartTime sets the server start time for uptime calculation.
func WithStartTime(t time.Time) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.startTime = t }
}

// WithTemplateService sets the policy template service.
func WithTemplateService(s *service.TemplateService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.templateService = s }
}

// SetRecordingService sets the FileRecorder after construction.
// Called from start.go after boot wiring creates the FileRecorder.
func (h *AdminAPIHandler) SetRecordingService(r *recording.FileRecorder) {
	h.recordingService = r
}

// SetRecordingObserver sets the RecordingObserver after construction.
// Called from start.go after boot wiring creates the RecordingObserver.
func (h *AdminAPIHandler) SetRecordingObserver(o *recording.RecordingObserver) {
	h.recordingObserver = o
}

// SetToolChangeNotifier sets the tool change notifier after construction.
// Called from start.go after boot wiring creates the HTTPToolChangeNotifier.
func (h *AdminAPIHandler) SetToolChangeNotifier(n service.ToolChangeNotifier) {
	h.toolChangeNotifier = n
}

// SetRetentionCleaner sets the RetentionCleaner after construction.
// Called from start.go so handlePutRecordingConfig can hot-reload the cleaner.
func (h *AdminAPIHandler) SetRetentionCleaner(c *recording.RetentionCleaner) {
	h.retentionCleaner = c
}

// SetEventBus sets the event bus for emitting admin events (e.g. whitelist changes).
func (h *AdminAPIHandler) SetEventBus(bus event.Bus) {
	h.eventBus = bus
}

// NewAdminAPIHandler creates a new AdminAPIHandler with the given options.
// After all options are applied, deferred initialization (e.g. CIDR parsing)
// runs with the fully configured logger (CONCERN-01).
func NewAdminAPIHandler(opts ...AdminAPIOption) *AdminAPIHandler {
	h := &AdminAPIHandler{
		logger:    slog.Default(),
		startTime: time.Now().UTC(),
	}
	for _, opt := range opts {
		opt(h)
	}
	// Deferred CIDR parsing — uses the final h.logger regardless of option order.
	h.applyTrustedProxies()
	return h
}

// applyTrustedProxies parses pendingProxyCIDRs into trustedProxies, logging
// warnings for invalid entries via the configured logger (not slog.Default()).
func (h *AdminAPIHandler) applyTrustedProxies() {
	for _, cidr := range h.pendingProxyCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			h.logger.Warn("invalid trusted proxy CIDR, skipping", "cidr", cidr, "error", err)
			continue
		}
		h.trustedProxies = append(h.trustedProxies, network)
	}
	h.pendingProxyCIDRs = nil
}

// Routes returns an http.Handler with all admin API routes registered.
// Auth status endpoint is accessible without auth middleware.
// All other admin API routes enforce localhost-only access.
func (h *AdminAPIHandler) Routes() http.Handler {
	mux := http.NewServeMux()

	// Auth status - NOT protected by auth middleware (informational).
	mux.HandleFunc("GET /admin/api/auth/status", h.handleAuthStatus)

	// All other routes are registered on a separate mux wrapped with auth middleware.
	protectedMux := http.NewServeMux()

	// Upstream CRUD + restart.
	protectedMux.HandleFunc("GET /admin/api/upstreams", h.handleListUpstreams)
	protectedMux.HandleFunc("POST /admin/api/upstreams", h.handleCreateUpstream)
	protectedMux.HandleFunc("PUT /admin/api/upstreams/{id}", h.handleUpdateUpstream)
	protectedMux.HandleFunc("DELETE /admin/api/upstreams/{id}", h.handleDeleteUpstream)
	protectedMux.HandleFunc("POST /admin/api/upstreams/{id}/restart", h.handleRestartUpstream)

	// Tool discovery.
	protectedMux.HandleFunc("GET /admin/api/tools", h.handleListTools)
	protectedMux.HandleFunc("POST /admin/api/tools/refresh", h.handleRefreshTools)

	// Policy CRUD.
	protectedMux.HandleFunc("GET /admin/api/policies", h.handleListPolicies)
	protectedMux.HandleFunc("POST /admin/api/policies", h.handleCreatePolicy)
	protectedMux.HandleFunc("POST /admin/api/policies/test", h.handleTestPolicy)
	protectedMux.HandleFunc("POST /admin/api/policies/lint", h.handleLintPolicy)
	protectedMux.HandleFunc("PUT /admin/api/policies/{id}", h.handleUpdatePolicy)
	protectedMux.HandleFunc("DELETE /admin/api/policies/{id}", h.handleDeletePolicy)
	protectedMux.HandleFunc("DELETE /admin/api/policies/{id}/rules/{ruleId}", h.handleDeleteRule)

	// Identity CRUD.
	protectedMux.HandleFunc("GET /admin/api/identities", h.handleListIdentities)
	protectedMux.HandleFunc("POST /admin/api/identities", h.handleCreateIdentity)
	protectedMux.HandleFunc("PUT /admin/api/identities/{id}", h.handleUpdateIdentity)
	protectedMux.HandleFunc("DELETE /admin/api/identities/{id}", h.handleDeleteIdentity)

	// API key management.
	protectedMux.HandleFunc("GET /admin/api/keys", h.handleListKeys)
	protectedMux.HandleFunc("POST /admin/api/keys", h.handleGenerateKey)
	protectedMux.HandleFunc("DELETE /admin/api/keys/{id}", h.handleRevokeKey)

	// Policy evaluation API (SDK / runtime agent access).
	protectedMux.HandleFunc("POST /admin/api/v1/policy/evaluate", h.handlePolicyEvaluate)
	protectedMux.HandleFunc("GET /admin/api/v1/policy/evaluate/{request_id}/status", h.handlePolicyEvaluateStatus)

	// HITL approval management.
	protectedMux.HandleFunc("GET /admin/api/v1/approvals", h.handleListApprovals)
	protectedMux.HandleFunc("GET /admin/api/v1/approvals/{id}/context", h.handleGetApprovalContext)
	protectedMux.HandleFunc("POST /admin/api/v1/approvals/{id}/approve", h.handleApproveRequest)
	protectedMux.HandleFunc("POST /admin/api/v1/approvals/{id}/deny", h.handleDenyRequest)

	// Content scanning configuration (response/output direction).
	protectedMux.HandleFunc("GET /admin/api/v1/security/content-scanning", h.handleGetContentScanning)
	protectedMux.HandleFunc("PUT /admin/api/v1/security/content-scanning", h.handleUpdateContentScanning)

	// Input content scanning (PII/secrets in arguments — Upgrade 3).
	protectedMux.HandleFunc("GET /admin/api/v1/security/input-scanning", h.handleGetInputScanning)
	protectedMux.HandleFunc("PUT /admin/api/v1/security/input-scanning", h.handleUpdateInputScanning)
	protectedMux.HandleFunc("POST /admin/api/v1/security/input-scanning/whitelist", h.handleAddWhitelist)
	protectedMux.HandleFunc("DELETE /admin/api/v1/security/input-scanning/whitelist/{id}", h.handleRemoveWhitelist)

	// Tool security: baseline, drift, quarantine.
	protectedMux.HandleFunc("POST /admin/api/v1/tools/baseline", h.handleCaptureBaseline)
	protectedMux.HandleFunc("GET /admin/api/v1/tools/baseline", h.handleGetBaseline)
	protectedMux.HandleFunc("GET /admin/api/v1/tools/drift", h.handleDetectDrift)
	protectedMux.HandleFunc("POST /admin/api/v1/tools/quarantine", h.handleQuarantineTool)
	protectedMux.HandleFunc("DELETE /admin/api/v1/tools/quarantine/{tool_name}", h.handleUnquarantineTool)
	protectedMux.HandleFunc("GET /admin/api/v1/tools/quarantine", h.handleListQuarantined)
	protectedMux.HandleFunc("POST /admin/api/v1/tools/accept-change", h.handleAcceptToolChange)

	// Policy templates (TMPL-01 through TMPL-04).
	protectedMux.HandleFunc("GET /admin/api/v1/templates", h.handleListTemplates)
	protectedMux.HandleFunc("GET /admin/api/v1/templates/{id}", h.handleGetTemplate)
	protectedMux.HandleFunc("POST /admin/api/v1/templates/{id}/apply", h.handleApplyTemplate)

	// Quota management (QUOT-05, QUOT-06).
	protectedMux.HandleFunc("GET /admin/api/v1/quotas", h.handleListQuotas)
	protectedMux.HandleFunc("GET /admin/api/v1/quotas/{identity_id}", h.handleGetQuota)
	protectedMux.HandleFunc("PUT /admin/api/v1/quotas/{identity_id}", h.handlePutQuota)
	protectedMux.HandleFunc("DELETE /admin/api/v1/quotas/{identity_id}", h.handleDeleteQuota)

	// Active sessions (QUOT-06).
	protectedMux.HandleFunc("GET /admin/api/v1/sessions/active", h.handleListActiveSessions)
	protectedMux.HandleFunc("DELETE /admin/api/v1/sessions/{id}", h.handleTerminateSession)

	// Unified Agent View (UX-F2).
	protectedMux.HandleFunc("GET /admin/api/v1/agents/{identity_id}/summary", h.handleGetAgentSummary)
	protectedMux.HandleFunc("POST /admin/api/v1/agents/{identity_id}/acknowledge", h.handleAcknowledgeAgentAlert)

	// Compliance (Upgrade 2).
	protectedMux.HandleFunc("GET /admin/api/v1/compliance/packs", h.handleListCompliancePacks)
	protectedMux.HandleFunc("GET /admin/api/v1/compliance/packs/{id}", h.handleGetCompliancePack)
	protectedMux.HandleFunc("POST /admin/api/v1/compliance/packs/{id}/coverage", h.handleGetComplianceCoverage)
	protectedMux.HandleFunc("POST /admin/api/v1/compliance/bundles", h.handleGenerateBundle)
	protectedMux.HandleFunc("GET /admin/api/v1/compliance/evidence", h.handleGetEvidenceConfig)
	protectedMux.HandleFunc("PUT /admin/api/v1/compliance/evidence", h.handlePutEvidenceConfig)

	// Policy Simulation (UX-F1).
	protectedMux.HandleFunc("POST /admin/api/v1/simulation/run", h.handleRunSimulation)

	// Behavioral Drift Detection (Upgrade 5).
	protectedMux.HandleFunc("GET /admin/api/v1/drift/reports", h.handleListDriftReports)
	protectedMux.HandleFunc("GET /admin/api/v1/drift/config", h.handleGetDriftConfig)
	protectedMux.HandleFunc("PUT /admin/api/v1/drift/config", h.handlePutDriftConfig)
	protectedMux.HandleFunc("GET /admin/api/v1/drift/profiles/{identity_id}", h.handleGetDriftProfile)
	protectedMux.HandleFunc("POST /admin/api/v1/drift/profiles/{identity_id}/reset", h.handleResetDriftBaseline)

	// Permission Health / Shadow Mode (Upgrade 6).
	protectedMux.HandleFunc("GET /admin/api/v1/permissions/health", h.handleGetAllPermissionHealth)
	protectedMux.HandleFunc("GET /admin/api/v1/permissions/health/{identity_id}", h.handleGetPermissionHealth)
	protectedMux.HandleFunc("GET /admin/api/v1/permissions/suggestions/{identity_id}", h.handleGetPermissionSuggestions)
	protectedMux.HandleFunc("POST /admin/api/v1/permissions/apply", h.handleApplySuggestions)
	protectedMux.HandleFunc("GET /admin/api/v1/permissions/config", h.handleGetPermissionHealthConfig)
	protectedMux.HandleFunc("PUT /admin/api/v1/permissions/config", h.handleUpdatePermissionHealthConfig)

	// Telemetry / OpenTelemetry (Upgrade 9).
	protectedMux.HandleFunc("GET /admin/api/v1/telemetry/config", h.handleGetTelemetryConfig)
	protectedMux.HandleFunc("PUT /admin/api/v1/telemetry/config", h.handlePutTelemetryConfig)

	// Namespace Isolation (Upgrade 8).
	protectedMux.HandleFunc("GET /admin/api/v1/namespaces/config", h.handleGetNamespaceConfig)
	protectedMux.HandleFunc("PUT /admin/api/v1/namespaces/config", h.handlePutNamespaceConfig)

	// Response transform rules (XFRM-08).
	protectedMux.HandleFunc("GET /admin/api/v1/transforms", h.handleListTransforms)
	protectedMux.HandleFunc("POST /admin/api/v1/transforms", h.handleCreateTransform)
	protectedMux.HandleFunc("POST /admin/api/v1/transforms/test", h.handleTestTransform)
	protectedMux.HandleFunc("GET /admin/api/v1/transforms/{id}", h.handleGetTransform)
	protectedMux.HandleFunc("PUT /admin/api/v1/transforms/{id}", h.handleUpdateTransform)
	protectedMux.HandleFunc("DELETE /admin/api/v1/transforms/{id}", h.handleDeleteTransform)

	// Session recordings (RECD-05, RECD-06).
	// config routes registered before {id} to prevent ServeMux matching "config" as an ID.
	protectedMux.HandleFunc("GET /admin/api/v1/recordings/config", h.handleGetRecordingConfig)
	protectedMux.HandleFunc("PUT /admin/api/v1/recordings/config", h.handlePutRecordingConfig)
	// events and export before bare {id} for the same reason.
	protectedMux.HandleFunc("GET /admin/api/v1/recordings/{id}/events", h.handleGetRecordingEvents)
	protectedMux.HandleFunc("GET /admin/api/v1/recordings/{id}/export", h.handleExportRecording)
	protectedMux.HandleFunc("DELETE /admin/api/v1/recordings/{id}", h.handleDeleteRecording)
	protectedMux.HandleFunc("GET /admin/api/v1/recordings/{id}", h.handleGetRecording)
	protectedMux.HandleFunc("GET /admin/api/v1/recordings", h.handleListRecordings)

	// Notification Center (UX-F3).
	protectedMux.HandleFunc("GET /admin/api/v1/notifications", h.handleListNotifications)
	protectedMux.HandleFunc("GET /admin/api/v1/notifications/count", h.handleNotificationCount)
	protectedMux.HandleFunc("GET /admin/api/v1/notifications/stream", h.handleNotificationStream)
	protectedMux.HandleFunc("POST /admin/api/v1/notifications/dismiss-all", h.handleDismissAllNotifications)
	protectedMux.HandleFunc("POST /admin/api/v1/notifications/{id}/dismiss", h.handleDismissNotification)

	// Red Team Testing (Upgrade 10).
	protectedMux.HandleFunc("POST /admin/api/v1/redteam/run", h.handleRunRedTeam)
	protectedMux.HandleFunc("POST /admin/api/v1/redteam/run/single", h.handleRunSingleRedTeam)
	protectedMux.HandleFunc("GET /admin/api/v1/redteam/corpus", h.handleGetRedTeamCorpus)
	protectedMux.HandleFunc("GET /admin/api/v1/redteam/reports", h.handleGetRedTeamReports)
	protectedMux.HandleFunc("GET /admin/api/v1/redteam/reports/{id}", h.handleGetRedTeamReport)

	// Agent Health Dashboard (Upgrade 11).
	protectedMux.HandleFunc("GET /admin/api/v1/agents/{identity_id}/health", h.handleGetAgentHealth)
	protectedMux.HandleFunc("GET /admin/api/v1/health/overview", h.handleGetHealthOverview)
	protectedMux.HandleFunc("GET /admin/api/v1/health/config", h.handleGetHealthConfig)
	protectedMux.HandleFunc("PUT /admin/api/v1/health/config", h.handlePutHealthConfig)

	// FinOps Cost Explorer (Upgrade 12).
	protectedMux.HandleFunc("GET /admin/api/v1/finops/costs", h.handleGetFinOpsCosts)
	protectedMux.HandleFunc("GET /admin/api/v1/finops/costs/{identity_id}", h.handleGetFinOpsIdentityCost)
	protectedMux.HandleFunc("GET /admin/api/v1/finops/budgets", h.handleGetFinOpsBudgets)
	protectedMux.HandleFunc("GET /admin/api/v1/finops/config", h.handleGetFinOpsConfig)
	protectedMux.HandleFunc("PUT /admin/api/v1/finops/config", h.handleUpdateFinOpsConfig)

	// Stats, system info, and audit endpoints.
	protectedMux.HandleFunc("GET /admin/api/stats", h.handleGetStats)
	protectedMux.HandleFunc("GET /admin/api/system", h.handleSystemInfo)
	protectedMux.HandleFunc("GET /admin/api/audit", h.handleQueryAudit)
	protectedMux.HandleFunc("GET /admin/api/audit/stream", h.handleAuditStream)
	protectedMux.HandleFunc("GET /admin/api/audit/export", h.handleAuditExport)

	// System management.
	protectedMux.HandleFunc("POST /admin/api/system/factory-reset", h.handleFactoryReset)

	// Wrap protected routes with auth middleware.
	mux.Handle("/admin/api/", h.adminAuthMiddleware(protectedMux))

	// SECU-09: Wrap with API rate limiter (3000 req/min/IP).
	// M-15: All connections including localhost are rate-limited to prevent CPU
	// exhaustion via compute-intensive operations (e.g. Argon2id hashing).
	// 3000/min (50/sec) prevents abuse while accommodating admin UI page loads
	// (each makes 5-10 API calls) and automated testing without false 429s.
	rateLimited := h.apiRateLimitMiddleware(3000, 1*time.Minute, mux)
	// Wrap with CSRF middleware (validates tokens on POST/PUT/DELETE).
	// NOTE (M-41): AdminHandler.Handler() also applies csrfMiddleware with the
	// same cookie name. This is intentional — Routes() serves /admin/api/* while
	// Handler() serves /admin/* (non-API). They are mounted on separate
	// compositeMux paths in boot_transport.go and never overlap, so each route
	// tree gets exactly one CSRF check.
	csrfProtected := h.csrfMiddlewareWithProxyTrust(rateLimited)
	// Wrap with CSP security headers (M-11: only trust X-Forwarded-Proto from trusted proxies).
	return cspMiddlewareWithTLS(csrfProtected, h.isTrustedProxy)
}

// internalError logs the actual error and responds with a generic message.
func (h *AdminAPIHandler) internalError(w http.ResponseWriter, msg string, err error) {
	h.logger.Error(msg, "error", err)
	h.respondError(w, http.StatusInternalServerError, "internal error")
}

// --- JSON helper methods ---

// respondJSON writes a JSON response with the given status code and data.
func (h *AdminAPIHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store") // L-64
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", "error", err)
	}
}

// respondError writes a JSON error response with the given status code and message.
func (h *AdminAPIHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{"error": message})
}

// maxBodySize is the maximum allowed request body size for admin API endpoints.
const maxBodySize = 10 * 1024 * 1024 // 10MB

// errBodyTooLarge is a sentinel error returned by readJSON when the request body
// exceeds maxBodySize. Callers should check errors.Is(err, errBodyTooLarge) and
// respond with 413 (M-38).
var errBodyTooLarge = errors.New("request body too large")

// readJSON decodes the request body into the given value.
// Enforces a maximum body size to prevent memory exhaustion attacks.
// Returns errBodyTooLarge when the body exceeds maxBodySize, so callers
// can return HTTP 413 per RFC 7231 (M-38).
// Uses io.LimitReader instead of http.MaxBytesReader(nil, ...) to avoid
// undefined behavior with a nil ResponseWriter (H-12).
func (h *AdminAPIHandler) readJSON(r *http.Request, v interface{}) error {
	lr := io.LimitReader(r.Body, maxBodySize+1)
	r.Body = io.NopCloser(lr)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return err
	}
	// Check whether there's more data beyond the limit. If we can read even
	// one more byte the body exceeded maxBodySize.
	probe := make([]byte, 1)
	if n, _ := lr.Read(probe); n > 0 {
		return errBodyTooLarge
	}
	return nil
}

// readJSONBody decodes the request body into v, writing an appropriate
// HTTP error response on failure: 413 for oversized bodies, 400 for
// malformed JSON. Returns true if decoding succeeded.
// Uses http.MaxBytesReader with the real ResponseWriter (H-12).
func (h *AdminAPIHandler) readJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			h.respondError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		}
		return false
	}
	return true
}

// handleReadJSONErr writes the appropriate HTTP error for a readJSON failure.
// Returns 413 for oversized bodies (errBodyTooLarge) and 400 for all other errors.
// Callers that use readJSON (which returns errBodyTooLarge) should prefer this
// over a hard-coded StatusBadRequest.
func (h *AdminAPIHandler) handleReadJSONErr(w http.ResponseWriter, err error) {
	if errors.Is(err, errBodyTooLarge) {
		h.respondError(w, http.StatusRequestEntityTooLarge, "request body too large")
	} else {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
	}
}

// pathParam extracts a named path parameter from the request URL.
// Uses Go 1.22+ PathValue.
func (h *AdminAPIHandler) pathParam(r *http.Request, name string) string {
	return r.PathValue(name)
}
