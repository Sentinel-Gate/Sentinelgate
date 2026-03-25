package admin

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// factoryResetMu prevents concurrent factory resets from interleaving.
var factoryResetMu sync.Mutex

// factoryResetResult summarises what the factory reset cleared.
type factoryResetResult struct {
	Success            bool     `json:"success"`
	UpstreamsRemoved   int      `json:"upstreams_removed"`
	PoliciesRemoved    int      `json:"policies_removed"`
	IdentitiesRemoved  int      `json:"identities_removed"`
	KeysRemoved        int      `json:"keys_removed"`
	QuotasRemoved      int      `json:"quotas_removed"`
	TransformsRemoved  int      `json:"transforms_removed"`
	SessionsCleared    int      `json:"sessions_cleared"`
	ApprovalsCancelled int      `json:"approvals_cancelled"`
	QuarantineCleared  int      `json:"quarantine_cleared"`
	RecordingsDeleted  int      `json:"recordings_deleted"`
	StatsReset         bool     `json:"stats_reset"`
	NotificationsReset bool     `json:"notifications_reset"`
	SkippedReadOnly    []string `json:"skipped_read_only,omitempty"`
}

// handleFactoryReset resets the running system to a clean state.
// It removes all upstreams, policies, identities, API keys, quotas,
// transforms, sessions, quarantined tools, and configuration — leaving
// only read-only resources seeded from YAML config.
// Audit logs are intentionally preserved for compliance.
//
// POST /admin/api/system/factory-reset
// Body: {"confirm": true}
func (h *AdminAPIHandler) handleFactoryReset(w http.ResponseWriter, r *http.Request) {
	// Require explicit confirmation.
	var body struct {
		Confirm bool `json:"confirm"`
	}
	if !h.readJSONBody(w, r, &body) {
		return
	}
	if !body.Confirm {
		h.respondError(w, http.StatusBadRequest, "factory reset requires {\"confirm\": true}")
		return
	}

	// Prevent concurrent resets from interleaving.
	if !factoryResetMu.TryLock() {
		h.respondError(w, http.StatusConflict, "factory reset already in progress")
		return
	}
	defer factoryResetMu.Unlock()

	ctx := r.Context()
	result := &factoryResetResult{}

	h.logger.Warn("factory reset initiated")

	// ── Phase 1: Cancel pending HITL approvals ────────────────────────
	// Must happen before identity/policy deletion to prevent approval
	// goroutines from resolving against deleted resources.
	if h.approvalStore != nil {
		pending := h.approvalStore.List()
		result.ApprovalsCancelled = len(pending)
		h.approvalStore.CancelAll()
	}

	// ── Phase 2: Stop upstreams and clear tool cache ──────────────────
	if h.upstreamService != nil {
		upstreams, err := h.upstreamService.List(ctx)
		if err != nil {
			h.logger.Error("factory reset: failed to list upstreams", "error", err)
		}
		for _, u := range upstreams {
			// Stop the live connection.
			if h.upstreamManager != nil {
				if err := h.upstreamManager.Stop(u.ID); err != nil {
					h.logger.Warn("factory reset: failed to stop upstream", "id", u.ID, "error", err)
				}
			}
			// Clear cached tools for this upstream.
			if h.toolCache != nil {
				h.toolCache.RemoveUpstream(u.ID)
			}
			// Delete from store + state.json.
			if err := h.upstreamService.Delete(ctx, u.ID); err != nil {
				h.logger.Warn("factory reset: failed to delete upstream", "id", u.ID, "error", err)
			} else {
				result.UpstreamsRemoved++
			}
		}
		if h.toolCache != nil {
			h.toolCache.ClearConflicts()
		}
	}

	// ── Phase 3: Delete all policies ──────────────────────────────────
	if h.policyAdminService != nil {
		policies, err := h.policyAdminService.List(ctx)
		if err != nil {
			h.logger.Error("factory reset: failed to list policies", "error", err)
		}
		for _, p := range policies {
			if err := h.policyAdminService.Delete(ctx, p.ID); err != nil {
				if errors.Is(err, service.ErrDefaultPolicyDelete) {
					result.SkippedReadOnly = append(result.SkippedReadOnly, "policy:"+p.Name)
				} else {
					h.logger.Warn("factory reset: failed to delete policy", "id", p.ID, "error", err)
				}
			} else {
				result.PoliciesRemoved++
			}
		}
	}

	// ── Phase 4: Delete all identities (cascades API keys) ────────────
	if h.identityService != nil {
		identities, err := h.identityService.ListIdentities(ctx)
		if err != nil {
			h.logger.Error("factory reset: failed to list identities", "error", err)
		}
		for _, id := range identities {
			deletedKeys, err := h.identityService.DeleteIdentity(ctx, id.ID)
			if err != nil {
				if errors.Is(err, service.ErrReadOnly) {
					result.SkippedReadOnly = append(result.SkippedReadOnly, "identity:"+id.Name)
				} else {
					h.logger.Warn("factory reset: failed to delete identity", "id", id.ID, "error", err)
				}
			} else {
				result.IdentitiesRemoved++
				result.KeysRemoved += len(deletedKeys)
				// Invalidate auth cache so connected agents are disconnected.
				if h.sessionCacheInvalidator != nil {
					h.sessionCacheInvalidator.InvalidateByIdentity(id.ID)
				}
			}
		}
	}

	// ── Phase 5: Delete all quotas ────────────────────────────────────
	if h.quotaStore != nil {
		quotas, err := h.quotaStore.List(ctx)
		if err != nil {
			h.logger.Error("factory reset: failed to list quotas", "error", err)
		}
		for _, q := range quotas {
			if err := h.quotaStore.Delete(ctx, q.IdentityID); err != nil {
				h.logger.Warn("factory reset: failed to delete quota", "identity_id", q.IdentityID, "error", err)
			} else {
				result.QuotasRemoved++
			}
		}
	}

	// ── Phase 6: Delete all transforms ────────────────────────────────
	if h.transformStore != nil {
		transforms, err := h.transformStore.List(ctx)
		if err != nil {
			h.logger.Error("factory reset: failed to list transforms", "error", err)
		}
		for _, t := range transforms {
			if err := h.transformStore.Delete(ctx, t.ID); err != nil {
				h.logger.Warn("factory reset: failed to delete transform", "id", t.ID, "error", err)
			} else {
				result.TransformsRemoved++
			}
		}
	}

	// ── Phase 7: Clear active sessions ────────────────────────────────
	if h.sessionTracker != nil {
		active := h.sessionTracker.ActiveSessions()
		for _, s := range active {
			h.sessionTracker.RemoveSession(s.SessionID)
		}
		result.SessionsCleared = len(active)
	}

	// ── Phase 8: Clear tool security (quarantine + baseline) ──────────
	if h.toolSecurityService != nil {
		quarantined := h.toolSecurityService.GetQuarantinedTools()
		for _, name := range quarantined {
			if err := h.toolSecurityService.Unquarantine(name); err != nil {
				h.logger.Warn("factory reset: failed to unquarantine tool", "tool", name, "error", err)
			} else {
				result.QuarantineCleared++
			}
		}
		// Clear baseline by loading empty state.
		emptyState := &state.AppState{
			ToolBaseline: make(map[string]state.ToolBaselineEntry),
		}
		h.toolSecurityService.LoadFromState(emptyState)
	}

	// ── Phase 8b: Reset content/input scanning to defaults ────────────
	if h.contentScanInterceptor != nil {
		h.contentScanInterceptor.SetEnabled(false)
		h.contentScanInterceptor.SetWhitelist(nil)
	}

	// ── Phase 8c: Reset response scanning to defaults ─────────────────
	if h.responseScanCtrl != nil {
		h.responseScanCtrl.SetEnabled(false)
		h.responseScanCtrl.SetMode(action.ScanModeMonitor)
	}
	for _, ctrl := range h.additionalScanCtrls {
		ctrl.SetEnabled(false)
		ctrl.SetMode(action.ScanModeMonitor)
	}

	// ── Phase 8d: Delete all session recording files from disk ────────
	if h.recordingService != nil {
		recordings, err := h.recordingService.ListRecordings()
		if err != nil {
			h.logger.Warn("factory reset: failed to list recordings", "error", err)
		}
		for _, rec := range recordings {
			if err := h.recordingService.DeleteRecording(rec.SessionID); err != nil {
				h.logger.Warn("factory reset: failed to delete recording", "session", rec.SessionID, "error", err)
			} else {
				result.RecordingsDeleted++
			}
		}
	}

	// ── Phase 9: Reset state.json config fields ───────────────────────
	// Clears configs that don't have dedicated in-memory stores,
	// and ensures in-memory deletions (quotas, transforms) are persisted.
	// Audit logs are intentionally preserved for compliance.
	if h.stateStore != nil {
		if err := h.stateStore.Mutate(func(s *state.AppState) error {
			s.Quotas = nil
			s.Transforms = nil
			s.ToolBaseline = nil
			s.QuarantinedTools = nil
			s.ContentScanningConfig = nil
			s.RecordingConfig = nil
			s.TelemetryConfig = nil
			s.NamespaceConfig = nil
			s.FinOpsConfig = nil
			s.HealthConfig = nil
			s.PermissionHealthConfig = nil
			s.DriftConfig = nil
			s.EvidenceConfig = nil
			s.PolicyEvaluations = nil
			s.UpdatedAt = time.Now().UTC()
			return nil
		}); err != nil {
			h.logger.Error("factory reset: failed to reset state.json configs", "error", err)
		}
	}

	// ── Phase 10: Reload policy service (now empty) ───────────────────
	if h.policyService != nil {
		if err := h.policyService.Reload(ctx); err != nil {
			h.logger.Error("factory reset: failed to reload policy service", "error", err)
		}
	}

	// ── Phase 10b: Clear audit ring buffer (UI-facing only) ──────────
	// The file/stdout audit trail is preserved for compliance. This only
	// clears the in-memory buffer used by Dashboard and Activity pages.
	type recentClearer interface{ ClearRecent() }
	if rc, ok := h.auditReader.(recentClearer); ok {
		rc.ClearRecent()
	}

	// ── Phase 11: Reset all in-memory service state ──────────────────
	// Clears caches, reports, configs that survive state.json deletion.

	if h.redteamService != nil {
		h.redteamService.ClearReports()
	}
	if h.healthService != nil {
		h.healthService.ClearCache()
		h.healthService.SetConfig(service.DefaultHealthConfig())
	}
	if h.notificationService != nil {
		h.notificationService.ClearAll()
		result.NotificationsReset = true
	}
	if h.policyEvalService != nil {
		h.policyEvalService.ClearEvaluations()
	}
	if h.driftService != nil {
		h.driftService.ClearCache()
		h.driftService.SetConfig(service.DefaultDriftConfig())
	}
	if h.permissionHealthService != nil {
		h.permissionHealthService.SetConfig(service.DefaultPermissionHealthConfig())
	}
	if h.namespaceService != nil {
		h.namespaceService.SetConfig(service.DefaultNamespaceConfig())
	}
	if h.finopsService != nil {
		h.finopsService.SetConfig(service.DefaultFinOpsConfig())
	}
	if h.telemetryService != nil {
		if err := h.telemetryService.SetConfig(service.DefaultTelemetryConfig()); err != nil {
			h.logger.Warn("factory reset: failed to reset telemetry config", "error", err)
		}
	}

	// ── Phase 12: Reset stats ─────────────────────────────────────────
	if h.statsService != nil {
		h.statsService.Reset()
		result.StatsReset = true
	}

	// ── Phase 13: Notify clients about tool list change ───────────────
	if h.toolChangeNotifier != nil {
		h.toolChangeNotifier.NotifyToolsChanged()
	}

	result.Success = true
	h.logger.Warn("factory reset completed",
		"upstreams", result.UpstreamsRemoved,
		"policies", result.PoliciesRemoved,
		"identities", result.IdentitiesRemoved,
		"keys", result.KeysRemoved,
		"quotas", result.QuotasRemoved,
		"transforms", result.TransformsRemoved,
		"sessions", result.SessionsCleared,
		"approvals", result.ApprovalsCancelled,
		"quarantine", result.QuarantineCleared,
		"recordings", result.RecordingsDeleted,
		"skipped", len(result.SkippedReadOnly),
	)

	h.respondJSON(w, http.StatusOK, result)
}
