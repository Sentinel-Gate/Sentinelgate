package admin

import (
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/quota"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/recording"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/transform"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// Sub-handler types define focused dependency groups for each API domain.
// New handlers for future upgrades (Evidence, Compliance, Integrity, etc.)
// should be methods on the appropriate sub-handler, NOT on AdminAPIHandler.
// This ensures new endpoints only depend on what they need (A2 decomposition).

// baseHandler provides the logger for all sub-handlers.
type baseHandler struct {
	logger *slog.Logger
}

// PolicySubHandler handles policy CRUD, evaluation, testing, and templates.
// Deps: 5 (vs 39 on AdminAPIHandler).
type PolicySubHandler struct {
	baseHandler
	policyService      *service.PolicyService
	policyAdminService *service.PolicyAdminService
	policyEvalService  *service.PolicyEvaluationService
	policyStore        policy.PolicyStore
	templateService    *service.TemplateService
	statsService       *service.StatsService
	auditService       *service.AuditService
}

// AuditSubHandler handles audit queries, SSE streaming, export, and recordings.
// Deps: 5 (vs 39 on AdminAPIHandler).
type AuditSubHandler struct {
	baseHandler
	auditService      *service.AuditService
	auditReader       AuditReader
	recordingService  *recording.FileRecorder
	recordingObserver *recording.RecordingObserver
	retentionCleaner  *recording.RetentionCleaner
	stateStore        *state.FileStateStore
}

// UpstreamSubHandler handles upstream management and tool discovery.
// Deps: 5 (vs 39 on AdminAPIHandler).
type UpstreamSubHandler struct {
	baseHandler
	upstreamService    *service.UpstreamService
	upstreamManager    *service.UpstreamManager
	discoveryService   *service.ToolDiscoveryService
	toolCache          *upstream.ToolCache
	toolChangeNotifier service.ToolChangeNotifier
	policyService      *service.PolicyService
	stateStore         *state.FileStateStore
}

// AccessSubHandler handles identities, API keys, approvals, quotas, and sessions.
// Deps: 5 (vs 39 on AdminAPIHandler).
type AccessSubHandler struct {
	baseHandler
	identityService *service.IdentityService
	approvalStore   *action.ApprovalStore
	quotaStore      quota.QuotaStore
	sessionTracker  *session.SessionTracker
	stateStore      *state.FileStateStore
}

// SecuritySubHandler handles content scanning and tool security.
type SecuritySubHandler struct {
	baseHandler
	responseScanCtrl     ResponseScanController
	additionalScanCtrls  []ResponseScanController
	toolSecurityService  *service.ToolSecurityService
	toolCache            *upstream.ToolCache
	stateStore           *state.FileStateStore
}

// TransformSubHandler handles response transformation rules.
// Deps: 3 (vs 39 on AdminAPIHandler).
type TransformSubHandler struct {
	baseHandler
	transformStore    transform.TransformStore
	transformExecutor *transform.TransformExecutor
	stateStore        *state.FileStateStore
}

// --- Factory methods on AdminAPIHandler ---
// These create sub-handlers with the appropriate deps from AdminAPIHandler's fields.
// Use these to instantiate sub-handlers for new domain-specific endpoints.

// PolicyHandlers returns a PolicySubHandler with the appropriate deps.
func (h *AdminAPIHandler) PolicyHandlers() *PolicySubHandler {
	return &PolicySubHandler{
		baseHandler:        baseHandler{logger: h.logger},
		policyService:      h.policyService,
		policyAdminService: h.policyAdminService,
		policyEvalService:  h.policyEvalService,
		policyStore:        h.policyStore,
		templateService:    h.templateService,
		statsService:       h.statsService,
		auditService:       h.auditService,
	}
}

// AuditHandlers returns an AuditSubHandler with the appropriate deps.
func (h *AdminAPIHandler) AuditHandlers() *AuditSubHandler {
	return &AuditSubHandler{
		baseHandler:       baseHandler{logger: h.logger},
		auditService:      h.auditService,
		auditReader:       h.auditReader,
		recordingService:  h.recordingService,
		recordingObserver: h.recordingObserver,
		retentionCleaner:  h.retentionCleaner,
		stateStore:        h.stateStore,
	}
}

// UpstreamHandlers returns an UpstreamSubHandler with the appropriate deps.
func (h *AdminAPIHandler) UpstreamHandlers() *UpstreamSubHandler {
	return &UpstreamSubHandler{
		baseHandler:        baseHandler{logger: h.logger},
		upstreamService:    h.upstreamService,
		upstreamManager:    h.upstreamManager,
		discoveryService:   h.discoveryService,
		toolCache:          h.toolCache,
		toolChangeNotifier: h.toolChangeNotifier,
		policyService:      h.policyService,
		stateStore:         h.stateStore,
	}
}

// AccessHandlers returns an AccessSubHandler with the appropriate deps.
func (h *AdminAPIHandler) AccessHandlers() *AccessSubHandler {
	return &AccessSubHandler{
		baseHandler:     baseHandler{logger: h.logger},
		identityService: h.identityService,
		approvalStore:   h.approvalStore,
		quotaStore:      h.quotaStore,
		sessionTracker:  h.sessionTracker,
		stateStore:      h.stateStore,
	}
}

// SecurityHandlers returns a SecuritySubHandler with the appropriate deps.
func (h *AdminAPIHandler) SecurityHandlers() *SecuritySubHandler {
	return &SecuritySubHandler{
		baseHandler:          baseHandler{logger: h.logger},
		responseScanCtrl:     h.responseScanCtrl,
		additionalScanCtrls:  h.additionalScanCtrls,
		toolSecurityService:  h.toolSecurityService,
		toolCache:            h.toolCache,
		stateStore:           h.stateStore,
	}
}

// TransformHandlers returns a TransformSubHandler with the appropriate deps.
func (h *AdminAPIHandler) TransformHandlers() *TransformSubHandler {
	return &TransformSubHandler{
		baseHandler:       baseHandler{logger: h.logger},
		transformStore:    h.transformStore,
		transformExecutor: h.transformExecutor,
		stateStore:        h.stateStore,
	}
}
