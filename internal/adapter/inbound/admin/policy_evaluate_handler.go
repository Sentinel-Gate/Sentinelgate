package admin

import (
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// WithPolicyEvalService sets the policy evaluation service on the AdminAPIHandler.
func WithPolicyEvalService(s *service.PolicyEvaluationService) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.policyEvalService = s }
}

// handlePolicyEvaluate processes POST /api/v1/policy/evaluate requests.
// It accepts a CanonicalAction-shaped request and returns a structured decision
// with help_url and help_text for deny/approval_required outcomes.
// Returns HTTP 200 for all evaluations (the decision is in the response body),
// HTTP 400 for invalid requests, and HTTP 500 for evaluation errors.
func (h *AdminAPIHandler) handlePolicyEvaluate(w http.ResponseWriter, r *http.Request) {
	if h.policyEvalService == nil {
		h.respondError(w, http.StatusInternalServerError, "policy evaluation service not configured")
		return
	}

	var req service.PolicyEvaluateRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate required fields.
	if req.ActionType == "" {
		h.respondError(w, http.StatusBadRequest, "action_type is required")
		return
	}
	if req.ActionName == "" {
		h.respondError(w, http.StatusBadRequest, "action_name is required")
		return
	}
	if req.IdentityName == "" {
		h.respondError(w, http.StatusBadRequest, "identity_name is required")
		return
	}
	if len(req.IdentityRoles) == 0 {
		h.respondError(w, http.StatusBadRequest, "identity_roles is required")
		return
	}

	resp, err := h.policyEvalService.Evaluate(r.Context(), req)
	if err != nil {
		h.logger.Error("policy evaluation failed", "error", err)
		h.respondError(w, http.StatusInternalServerError, "policy evaluation failed")
		return
	}

	// Record protocol/framework stats from the evaluation request.
	if h.statsService != nil {
		if req.Protocol != "" {
			h.statsService.RecordProtocol(req.Protocol)
		}
		if req.Framework != "" {
			h.statsService.RecordFramework(req.Framework)
		}
	}

	// Record audit entry so runtime hook evaluations appear in the audit log.
	if h.auditService != nil {
		record := audit.AuditRecord{
			Timestamp:     time.Now(),
			ToolName:      req.ActionName,
			ToolArguments: req.Arguments,
			Decision:      resp.Decision,
			Reason:        resp.Reason,
			RuleID:        resp.RuleID,
			RequestID:     resp.RequestID,
			LatencyMicros: resp.LatencyMs * 1000,
			Protocol:      req.Protocol,
			Framework:     req.Framework,
			IdentityName:  req.IdentityName,
		}
		h.auditService.Record(record)
	}

	h.respondJSON(w, http.StatusOK, resp)
}

// PolicyEvaluateStatusResponse is the response for GET /api/v1/policy/evaluate/{request_id}/status.
type PolicyEvaluateStatusResponse struct {
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Decision  string `json:"decision"`
	UpdatedAt string `json:"updated_at"`
}

// handlePolicyEvaluateStatus processes GET /api/v1/policy/evaluate/{request_id}/status requests.
// It returns the approval polling status for a previously submitted evaluation.
// Returns HTTP 200 with status JSON, or HTTP 404 if the request_id is not found.
func (h *AdminAPIHandler) handlePolicyEvaluateStatus(w http.ResponseWriter, r *http.Request) {
	if h.policyEvalService == nil {
		h.respondError(w, http.StatusInternalServerError, "policy evaluation service not configured")
		return
	}

	requestID := h.pathParam(r, "request_id")
	if requestID == "" {
		h.respondError(w, http.StatusBadRequest, "request_id is required")
		return
	}

	eval := h.policyEvalService.GetEvaluationStatus(requestID)
	if eval == nil {
		h.respondError(w, http.StatusNotFound, "evaluation not found")
		return
	}

	resp := PolicyEvaluateStatusResponse{
		RequestID: eval.RequestID,
		Status:    eval.Status,
		Decision:  eval.Decision,
		UpdatedAt: eval.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}

	h.respondJSON(w, http.StatusOK, resp)
}
