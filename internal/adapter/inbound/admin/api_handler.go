// Package admin provides web UI and JSON API handlers for Sentinel Gate.
package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// AuditReader provides read access to recent audit records for the admin API.
// This is a minimal interface used by the admin API; full query support is in audit.AuditQueryStore.
type AuditReader interface {
	// GetRecent returns the N most recent audit records.
	GetRecent(n int) []audit.AuditRecord
	// Query retrieves audit records matching the filter.
	Query(filter audit.AuditFilter) ([]audit.AuditRecord, string, error)
}

// AdminAPIHandler provides JSON API endpoints for the admin interface.
// It coexists with the legacy AdminHandler which serves the template-based UI.
type AdminAPIHandler struct {
	upstreamService      *service.UpstreamService
	upstreamManager      *service.UpstreamManager
	discoveryService     *service.ToolDiscoveryService
	toolCache            *upstream.ToolCache
	policyService        *service.PolicyService
	policyStore          policy.PolicyStore
	auditService         *service.AuditService
	auditReader          AuditReader
	statsService         *service.StatsService
	identityService      *service.IdentityService
	policyEvalService    *service.PolicyEvaluationService
	policyAdminService   *service.PolicyAdminService
	outboundAdminService *service.OutboundAdminService
	stateStore           *state.FileStateStore
	authStore            *memory.AuthStore
	approvalStore        *action.ApprovalStore
	responseScanCtrl     ResponseScanController
	additionalScanCtrls  []ResponseScanController
	httpGatewayCtrl      HTTPGatewayController
	toolSecurityService  *service.ToolSecurityService
	agentRegistry        *service.AgentRegistry
	buildInfo            *BuildInfo
	logger               *slog.Logger
	startTime            time.Time
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

// WithAuthStore sets the in-memory auth store for syncing keys on creation/revocation.
func WithAuthStore(s *memory.AuthStore) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.authStore = s }
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

// WithStartTime sets the server start time for uptime calculation.
func WithStartTime(t time.Time) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.startTime = t }
}

// WithOutboundAdminService sets the outbound rule admin service.
func WithOutboundAdminService(s *service.OutboundAdminService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.outboundAdminService = s }
}

// SetOutboundAdminService sets the outbound admin service after construction.
// This is needed when the service is created after the AdminAPIHandler (due to
// boot sequence ordering where BOOT-07 builds the interceptor chain after services).
func (h *AdminAPIHandler) SetOutboundAdminService(s *service.OutboundAdminService) {
	h.outboundAdminService = s
}

// NewAdminAPIHandler creates a new AdminAPIHandler with the given options.
func NewAdminAPIHandler(opts ...AdminAPIOption) *AdminAPIHandler {
	h := &AdminAPIHandler{
		logger:    slog.Default(),
		startTime: time.Now().UTC(),
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
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
	protectedMux.HandleFunc("PUT /admin/api/policies/{id}", h.handleUpdatePolicy)
	protectedMux.HandleFunc("DELETE /admin/api/policies/{id}", h.handleDeletePolicy)

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
	protectedMux.HandleFunc("POST /admin/api/v1/approvals/{id}/approve", h.handleApproveRequest)
	protectedMux.HandleFunc("POST /admin/api/v1/approvals/{id}/deny", h.handleDenyRequest)

	// Content scanning configuration.
	protectedMux.HandleFunc("GET /admin/api/v1/security/content-scanning", h.handleGetContentScanning)
	protectedMux.HandleFunc("PUT /admin/api/v1/security/content-scanning", h.handleUpdateContentScanning)

	// HTTP Gateway configuration.
	protectedMux.HandleFunc("GET /admin/api/v1/security/http-gateway", h.handleGetHTTPGatewayConfig)
	protectedMux.HandleFunc("PUT /admin/api/v1/security/http-gateway/tls", h.handlePutHTTPGatewayTLS)
	protectedMux.HandleFunc("GET /admin/api/v1/security/http-gateway/ca-cert", h.handleGetCACert)
	protectedMux.HandleFunc("GET /admin/api/v1/security/http-gateway/setup-script", h.handleGetSetupScript)
	protectedMux.HandleFunc("POST /admin/api/v1/security/http-gateway/targets", h.handleCreateTarget)
	protectedMux.HandleFunc("PUT /admin/api/v1/security/http-gateway/targets/{id}", h.handleUpdateTarget)
	protectedMux.HandleFunc("DELETE /admin/api/v1/security/http-gateway/targets/{id}", h.handleDeleteTarget)

	// Outbound control: rule CRUD, test, stats.
	protectedMux.HandleFunc("GET /admin/api/v1/security/outbound/rules", h.handleListOutboundRules)
	protectedMux.HandleFunc("GET /admin/api/v1/security/outbound/rules/{id}", h.handleGetOutboundRule)
	protectedMux.HandleFunc("POST /admin/api/v1/security/outbound/rules", h.handleCreateOutboundRule)
	protectedMux.HandleFunc("PUT /admin/api/v1/security/outbound/rules/{id}", h.handleUpdateOutboundRule)
	protectedMux.HandleFunc("DELETE /admin/api/v1/security/outbound/rules/{id}", h.handleDeleteOutboundRule)
	protectedMux.HandleFunc("POST /admin/api/v1/security/outbound/test", h.handleTestOutbound)
	protectedMux.HandleFunc("GET /admin/api/v1/security/outbound/stats", h.handleOutboundStats)

	// Tool security: baseline, drift, quarantine.
	protectedMux.HandleFunc("POST /admin/api/v1/tools/baseline", h.handleCaptureBaseline)
	protectedMux.HandleFunc("GET /admin/api/v1/tools/baseline", h.handleGetBaseline)
	protectedMux.HandleFunc("GET /admin/api/v1/tools/drift", h.handleDetectDrift)
	protectedMux.HandleFunc("POST /admin/api/v1/tools/quarantine", h.handleQuarantineTool)
	protectedMux.HandleFunc("DELETE /admin/api/v1/tools/quarantine/{tool_name}", h.handleUnquarantineTool)
	protectedMux.HandleFunc("GET /admin/api/v1/tools/quarantine", h.handleListQuarantined)

	// Agent registry endpoints.
	protectedMux.HandleFunc("GET /admin/api/agents", h.handleListAgents)
	protectedMux.HandleFunc("GET /admin/api/agents/env", h.handleGetAgentEnv)
	protectedMux.HandleFunc("POST /admin/api/agents/register", h.handleRegisterAgent)
	protectedMux.HandleFunc("DELETE /admin/api/agents/{id}", h.handleUnregisterAgent)

	// Stats, system info, and audit endpoints.
	protectedMux.HandleFunc("GET /admin/api/stats", h.handleGetStats)
	protectedMux.HandleFunc("GET /admin/api/system", h.handleSystemInfo)
	protectedMux.HandleFunc("GET /admin/api/audit", h.handleQueryAudit)
	protectedMux.HandleFunc("GET /admin/api/audit/stream", h.handleAuditStream)
	protectedMux.HandleFunc("GET /admin/api/audit/export", h.handleAuditExport)

	// Wrap protected routes with auth middleware.
	mux.Handle("/admin/api/", h.adminAuthMiddleware(protectedMux))

	// SECU-09: Wrap with API rate limiter (60 req/min/IP, localhost exempt).
	rateLimited := apiRateLimitMiddleware(60, 1*time.Minute, mux)
	// Wrap with CSRF middleware (validates tokens on POST/PUT/DELETE).
	csrfProtected := csrfMiddleware(rateLimited)
	// Wrap with CSP security headers.
	return cspMiddleware(csrfProtected)
}

// --- JSON helper methods ---

// respondJSON writes a JSON response with the given status code and data.
func (h *AdminAPIHandler) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", "error", err)
	}
}

// respondError writes a JSON error response with the given status code and message.
func (h *AdminAPIHandler) respondError(w http.ResponseWriter, status int, message string) {
	h.respondJSON(w, status, map[string]string{"error": message})
}

// readJSON decodes the request body into the given value.
// Returns an error if the body cannot be decoded as JSON.
func (h *AdminAPIHandler) readJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// pathParam extracts a named path parameter from the request URL.
// Uses Go 1.22+ PathValue.
func (h *AdminAPIHandler) pathParam(r *http.Request, name string) string {
	return r.PathValue(name)
}
