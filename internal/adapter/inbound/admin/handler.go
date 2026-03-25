// Package admin provides a web UI for Sentinel Gate OSS.
// Allows viewing and editing policies and rules.
package admin

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// AuditEntry represents a single audit log entry for display.
type AuditEntry struct {
	Timestamp  string
	IdentityID string
	ToolName   string
	Decision   string
}

// AdminHandler handles the admin UI routes.
type AdminHandler struct {
	cfg        *config.OSSConfig
	configPath string
	logger     *slog.Logger
	tmpl       *template.Template
	mu         sync.RWMutex // Protects cfg
	version    string

	// In-memory log buffer for display (last N entries)
	logBuffer []AuditEntry
	logMu     sync.RWMutex
	maxLogs   int

	// Callback to notify policy changes
	onPolicyChange func()
}

// NewAdminHandler creates a new admin UI handler.
func NewAdminHandler(cfg *config.OSSConfig, logger *slog.Logger) (*AdminHandler, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	return &AdminHandler{
		cfg:        cfg,
		configPath: config.ConfigFileUsed(),
		logger:     logger,
		tmpl:       tmpl,
		logBuffer:  make([]AuditEntry, 0, 100),
		maxLogs:    100,
	}, nil
}

// SetOnPolicyChange sets a callback function that will be called when policies change.
func (h *AdminHandler) SetOnPolicyChange(fn func()) {
	h.mu.Lock()
	h.onPolicyChange = fn
	h.mu.Unlock()
}

// SetVersion sets the version string displayed in the SPA sidebar.
func (h *AdminHandler) SetVersion(v string) {
	h.mu.Lock()
	h.version = v
	h.mu.Unlock()
}

// spaPage renders the single-page application layout shell.
// L-22: Render into bytes.Buffer first; write to ResponseWriter only on success.
func (h *AdminHandler) spaPage(w http.ResponseWriter, r *http.Request) {
	v := h.version
	if v == "" {
		v = "dev"
	}
	data := map[string]interface{}{"Version": v}

	var buf bytes.Buffer
	if err := h.tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		h.logger.Error("failed to render SPA layout template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8") // M-37
	_, _ = w.Write(buf.Bytes())
}

// AddLogEntry adds an audit entry to the in-memory buffer for display.
func (h *AdminHandler) AddLogEntry(entry AuditEntry) {
	h.logMu.Lock()
	defer h.logMu.Unlock()

	h.logBuffer = append([]AuditEntry{entry}, h.logBuffer...)
	if len(h.logBuffer) > h.maxLogs {
		h.logBuffer = h.logBuffer[:h.maxLogs]
	}
}

// Handler returns an http.Handler with all admin routes.
func (h *AdminHandler) Handler() http.Handler {
	mux := http.NewServeMux()

	// Static files (no auth, no-cache for JS to prevent stale code)
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// M-49: fs.Sub on an embedded FS with a valid path must not fail at init time.
		// If it does, the binary is malformed — panic immediately rather than silently serve nothing.
		panic("admin: failed to sub static filesystem: " + err.Error())
	}
	staticHandler := http.StripPrefix("/admin/static/", http.FileServer(http.FS(staticSub)))
	mux.Handle("GET /admin/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		staticHandler.ServeHTTP(w, r)
	}))

	// SPA shell (auth required)
	mux.HandleFunc("GET /admin", h.requireAuth(h.spaPage))
	mux.HandleFunc("GET /admin/", h.requireAuth(h.spaPage))

	// API endpoints (auth required)
	mux.HandleFunc("GET /admin/api/rules", h.requireAuth(h.listRules))
	mux.HandleFunc("POST /admin/api/rules", h.requireAuth(h.createRule))
	mux.HandleFunc("PUT /admin/api/rules", h.requireAuth(h.updateRule))
	mux.HandleFunc("DELETE /admin/api/rules", h.requireAuth(h.deleteRule))

	// NOTE (M-41): AdminAPIHandler.Routes() also applies csrfMiddleware with
	// the same cookie name. This is intentional — Handler() serves /admin/*
	// (non-API template UI) while Routes() serves /admin/api/*. They are
	// mounted on separate compositeMux paths in boot_transport.go and never
	// overlap, so each route tree gets exactly one CSRF check.
	return cspMiddleware(csrfMiddleware(mux))
}

// requireAuth wraps a handler with authentication check.
// Admin UI is localhost-only in OSS. Remote access requires SSH tunnel
// or the Pro version with SSO/SAML.
func (h *AdminHandler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isLocalhost(r) {
			next(w, r)
			return
		}
		// Remote access not supported in OSS — use SSH tunnel.
		if strings.HasPrefix(r.URL.Path, "/admin/api/") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"admin UI requires localhost access"}`))
			return
		}
		http.Error(w, "Admin UI requires localhost access. Use: ssh -L 8080:localhost:8080 yourserver", http.StatusForbidden)
	}
}

// RuleRequest is the JSON request for creating/updating a rule.
type RuleRequest struct {
	PolicyIndex int    `json:"policyIndex"`
	RuleIndex   int    `json:"ruleIndex"` // -1 for new rule
	Name        string `json:"name"`
	Condition   string `json:"condition"`
	Action      string `json:"action"`
}

// listRules returns all rules as JSON.
func (h *AdminHandler) listRules(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(h.cfg.Policies); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// legacyError writes a JSON error response with correct Content-Type (M-44).
// L-38: Uses json.Marshal to properly escape the message, preventing JSON injection
// if msg contains special characters like double quotes.
func legacyError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	resp := map[string]string{"error": msg}
	data, err := json.Marshal(resp)
	if err != nil {
		// Fallback: this should never fail for map[string]string, but be safe.
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
		return
	}
	_, _ = w.Write(data)
}

// createRule adds a new rule.
func (h *AdminHandler) createRule(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize) // M-43
	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		legacyError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if req.PolicyIndex < 0 || req.PolicyIndex >= len(h.cfg.Policies) {
		legacyError(w, "invalid policy index", http.StatusBadRequest)
		return
	}

	cond := req.Condition
	if cond == "" {
		cond = "true" // default: match all calls
	}
	newRule := config.RuleConfig{
		Name:      req.Name,
		Condition: cond,
		Action:    req.Action,
	}

	origRules := h.cfg.Policies[req.PolicyIndex].Rules
	h.cfg.Policies[req.PolicyIndex].Rules = append(append([]config.RuleConfig(nil), origRules...), newRule)

	if err := h.saveConfig(); err != nil {
		h.cfg.Policies[req.PolicyIndex].Rules = origRules
		h.logger.Error("failed to save config", "error", err)
		legacyError(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// updateRule modifies an existing rule.
func (h *AdminHandler) updateRule(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize) // M-43
	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		legacyError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if req.PolicyIndex < 0 || req.PolicyIndex >= len(h.cfg.Policies) {
		legacyError(w, "invalid policy index", http.StatusBadRequest)
		return
	}

	if req.RuleIndex < 0 || req.RuleIndex >= len(h.cfg.Policies[req.PolicyIndex].Rules) {
		legacyError(w, "invalid rule index", http.StatusBadRequest)
		return
	}

	cond := req.Condition
	if cond == "" {
		cond = "true" // default: match all calls
	}
	origRule := h.cfg.Policies[req.PolicyIndex].Rules[req.RuleIndex]
	h.cfg.Policies[req.PolicyIndex].Rules[req.RuleIndex] = config.RuleConfig{
		Name:      req.Name,
		Condition: cond,
		Action:    req.Action,
	}

	if err := h.saveConfig(); err != nil {
		h.cfg.Policies[req.PolicyIndex].Rules[req.RuleIndex] = origRule
		h.logger.Error("failed to save config", "error", err)
		legacyError(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// deleteRule removes a rule.
func (h *AdminHandler) deleteRule(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize) // M-43
	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		legacyError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if req.PolicyIndex < 0 || req.PolicyIndex >= len(h.cfg.Policies) {
		legacyError(w, "invalid policy index", http.StatusBadRequest)
		return
	}

	rules := h.cfg.Policies[req.PolicyIndex].Rules
	if req.RuleIndex < 0 || req.RuleIndex >= len(rules) {
		legacyError(w, "invalid rule index", http.StatusBadRequest)
		return
	}

	// L-39: Build a new slice to avoid corrupting origRules via shared backing array.
	origRules := make([]config.RuleConfig, len(rules))
	copy(origRules, rules)
	newRules := make([]config.RuleConfig, 0, len(rules)-1)
	newRules = append(newRules, rules[:req.RuleIndex]...)
	newRules = append(newRules, rules[req.RuleIndex+1:]...)
	h.cfg.Policies[req.PolicyIndex].Rules = newRules

	if err := h.saveConfig(); err != nil {
		h.cfg.Policies[req.PolicyIndex].Rules = origRules
		h.logger.Error("failed to save config", "error", err)
		legacyError(w, "failed to save config", http.StatusInternalServerError)
		return
	}

	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		h.logger.Error("failed to encode response", "error", err)
	}
}

// saveConfig writes the current config to the YAML file.
// H-7/H-10: Uses atomic write pattern (temp file + fsync + rename) to prevent
// partial writes from leaving a corrupt config file on crash.
func (h *AdminHandler) saveConfig() error {
	if h.configPath == "" {
		return nil // No config file to save to
	}

	data, err := yaml.Marshal(h.cfg)
	if err != nil {
		return err
	}

	dir := filepath.Dir(h.configPath)
	tmp, err := os.CreateTemp(dir, ".sentinelgate-config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, h.configPath)
}

// CreateAuditEntry creates an AuditEntry from audit record data.
func CreateAuditEntry(identityID, toolName, decision string) AuditEntry {
	return AuditEntry{
		Timestamp:  time.Now().UTC().Format("15:04:05"),
		IdentityID: identityID,
		ToolName:   toolName,
		Decision:   decision,
	}
}
