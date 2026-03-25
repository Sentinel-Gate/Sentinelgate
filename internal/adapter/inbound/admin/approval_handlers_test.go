package admin

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

type approvalTestEnv struct {
	handler       *AdminAPIHandler
	approvalStore *action.ApprovalStore
	mux           http.Handler
}

func setupApprovalTestEnv(t *testing.T) *approvalTestEnv {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	store := action.NewApprovalStore(100)
	handler := NewAdminAPIHandler(
		WithApprovalStore(store),
		WithAPILogger(logger),
	)
	return &approvalTestEnv{
		handler:       handler,
		approvalStore: store,
		mux:           handler.Routes(),
	}
}

// approvalCSRFToken is a fixed CSRF token used across approval handler tests.
const approvalCSRFToken = "test-csrf-token-for-approval-tests"

func (e *approvalTestEnv) doRequest(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		bodyReader = bytes.NewReader(data)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.RemoteAddr = "127.0.0.1:1234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Include CSRF token on state-changing requests.
	if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete {
		req.AddCookie(&http.Cookie{Name: "sentinel_csrf_token", Value: approvalCSRFToken})
		req.Header.Set("X-CSRF-Token", approvalCSRFToken)
	}
	rec := httptest.NewRecorder()
	e.mux.ServeHTTP(rec, req)
	return rec
}

func decodeApprovalJSON(t *testing.T, rec *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(rec.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v (body=%q)", err, rec.Body.String())
	}
}

// addTestApproval adds a PendingApproval to the store and returns it.
func addTestApproval(t *testing.T, store *action.ApprovalStore, id string) *action.PendingApproval {
	t.Helper()
	p := action.NewTestPendingApproval(
		id,
		"delete_database",
		"agent-1",
		"identity-001",
		"session-abc",
		"rule-42",
		"dangerous-ops",
		5*time.Minute,
	)
	if err := store.Add(p); err != nil {
		t.Fatalf("store.Add: %v", err)
	}
	return p
}

// --- List Approvals ---

func TestHandleListApprovals_Empty(t *testing.T) {
	env := setupApprovalTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/approvals", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/approvals status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []approvalResponse
	decodeApprovalJSON(t, rec, &result)
	if len(result) != 0 {
		t.Errorf("response count = %d, want 0", len(result))
	}
}

func TestHandleListApprovals_WithPending(t *testing.T) {
	env := setupApprovalTestEnv(t)
	addTestApproval(t, env.approvalStore, "appr-001")

	rec := env.doRequest(t, "GET", "/admin/api/v1/approvals", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/v1/approvals status = %d, want %d", rec.Code, http.StatusOK)
	}

	var result []approvalResponse
	decodeApprovalJSON(t, rec, &result)
	if len(result) != 1 {
		t.Fatalf("response count = %d, want 1", len(result))
	}
	if result[0].ID != "appr-001" {
		t.Errorf("response ID = %q, want %q", result[0].ID, "appr-001")
	}
	if result[0].ToolName != "delete_database" {
		t.Errorf("response ToolName = %q, want %q", result[0].ToolName, "delete_database")
	}
	if result[0].IdentityName != "agent-1" {
		t.Errorf("response IdentityName = %q, want %q", result[0].IdentityName, "agent-1")
	}
	if result[0].Status != "pending" {
		t.Errorf("response Status = %q, want %q", result[0].Status, "pending")
	}
}

// --- Approve Request ---

func TestHandleApproveRequest(t *testing.T) {
	env := setupApprovalTestEnv(t)
	addTestApproval(t, env.approvalStore, "appr-002")

	rec := env.doRequest(t, "POST", "/admin/api/v1/approvals/appr-002/approve", map[string]string{
		"note": "looks good",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST approve status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]string
	decodeApprovalJSON(t, rec, &result)
	if result["status"] != "approved" {
		t.Errorf("response status = %q, want %q", result["status"], "approved")
	}
	if result["id"] != "appr-002" {
		t.Errorf("response id = %q, want %q", result["id"], "appr-002")
	}
}

func TestHandleApproveRequest_NotFound(t *testing.T) {
	env := setupApprovalTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/approvals/nonexistent/approve", map[string]string{
		"note": "test",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST approve nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleApproveRequest_AlreadyResolved(t *testing.T) {
	env := setupApprovalTestEnv(t)
	addTestApproval(t, env.approvalStore, "appr-003")

	// Approve once.
	env.doRequest(t, "POST", "/admin/api/v1/approvals/appr-003/approve", nil)

	// Approve again -- should conflict.
	rec := env.doRequest(t, "POST", "/admin/api/v1/approvals/appr-003/approve", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST approve already resolved status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

// --- Deny Request ---

func TestHandleDenyRequest(t *testing.T) {
	env := setupApprovalTestEnv(t)
	addTestApproval(t, env.approvalStore, "appr-004")

	rec := env.doRequest(t, "POST", "/admin/api/v1/approvals/appr-004/deny", map[string]string{
		"reason": "too risky",
		"note":   "needs review",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST deny status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]string
	decodeApprovalJSON(t, rec, &result)
	if result["status"] != "denied" {
		t.Errorf("response status = %q, want %q", result["status"], "denied")
	}
	if result["id"] != "appr-004" {
		t.Errorf("response id = %q, want %q", result["id"], "appr-004")
	}
	if result["message"] != "too risky" {
		t.Errorf("response message = %q, want %q", result["message"], "too risky")
	}
}

func TestHandleDenyRequest_NotFound(t *testing.T) {
	env := setupApprovalTestEnv(t)

	rec := env.doRequest(t, "POST", "/admin/api/v1/approvals/nonexistent/deny", map[string]string{
		"reason": "test",
	})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST deny nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestHandleDenyRequest_AlreadyResolved(t *testing.T) {
	env := setupApprovalTestEnv(t)
	addTestApproval(t, env.approvalStore, "appr-005")

	// Deny once.
	env.doRequest(t, "POST", "/admin/api/v1/approvals/appr-005/deny", map[string]string{
		"reason": "nope",
	})

	// Deny again -- should conflict.
	rec := env.doRequest(t, "POST", "/admin/api/v1/approvals/appr-005/deny", map[string]string{
		"reason": "nope again",
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST deny already resolved status = %d, want %d (body=%s)", rec.Code, http.StatusConflict, rec.Body.String())
	}
}

func TestHandleDenyRequest_DefaultReason(t *testing.T) {
	env := setupApprovalTestEnv(t)
	addTestApproval(t, env.approvalStore, "appr-006")

	// Deny without providing a reason.
	rec := env.doRequest(t, "POST", "/admin/api/v1/approvals/appr-006/deny", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST deny default reason status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]string
	decodeApprovalJSON(t, rec, &result)
	if result["message"] != "denied by admin" {
		t.Errorf("response message = %q, want %q", result["message"], "denied by admin")
	}
}

// --- Get Approval Context ---

func TestHandleGetApprovalContext(t *testing.T) {
	env := setupApprovalTestEnv(t)
	addTestApproval(t, env.approvalStore, "appr-007")

	rec := env.doRequest(t, "GET", "/admin/api/v1/approvals/appr-007/context", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET context status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result approvalContextResponse
	decodeApprovalJSON(t, rec, &result)
	if result.Request.ID != "appr-007" {
		t.Errorf("context request ID = %q, want %q", result.Request.ID, "appr-007")
	}
	if result.Request.ToolName != "delete_database" {
		t.Errorf("context request ToolName = %q, want %q", result.Request.ToolName, "delete_database")
	}
	if result.Request.IdentityName != "agent-1" {
		t.Errorf("context request IdentityName = %q, want %q", result.Request.IdentityName, "agent-1")
	}
	if result.Request.IdentityID != "identity-001" {
		t.Errorf("context request IdentityID = %q, want %q", result.Request.IdentityID, "identity-001")
	}
	// Without an auditReader, session_trail should be empty (no audit data).
	if len(result.SessionTrail) != 0 {
		t.Errorf("session trail count = %d, want 0 (no auditReader)", len(result.SessionTrail))
	}
	// Assessment should include "Agent has never used delete_database before".
	if len(result.Assessment) == 0 {
		t.Error("assessment should not be empty")
	}
}

func TestHandleGetApprovalContext_NotFound(t *testing.T) {
	env := setupApprovalTestEnv(t)

	rec := env.doRequest(t, "GET", "/admin/api/v1/approvals/nonexistent/context", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET context nonexistent status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
