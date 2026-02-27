// Package admin provides a web UI for Sentinel Gate OSS.
// Allows viewing and editing policies and rules.
package admin

import (
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
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
	h.onPolicyChange = fn
}

// SetVersion sets the version string displayed in the SPA sidebar.
func (h *AdminHandler) SetVersion(v string) { h.version = v }

// spaPage renders the single-page application layout shell.
func (h *AdminHandler) spaPage(w http.ResponseWriter, r *http.Request) {
	v := h.version
	if v == "" {
		v = "dev"
	}
	data := map[string]interface{}{"Version": v}
	_ = h.tmpl.ExecuteTemplate(w, "layout", data)
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
	staticSub, _ := fs.Sub(staticFS, "static")
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

	return cspMiddleware(mux)
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
			http.Error(w, `{"error":"admin UI requires localhost access"}`, http.StatusForbidden)
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
	_ = json.NewEncoder(w).Encode(h.cfg.Policies)
}

// createRule adds a new rule.
func (h *AdminHandler) createRule(w http.ResponseWriter, r *http.Request) {
	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if req.PolicyIndex < 0 || req.PolicyIndex >= len(h.cfg.Policies) {
		http.Error(w, `{"error":"invalid policy index"}`, http.StatusBadRequest)
		return
	}

	newRule := config.RuleConfig{
		Name:      req.Name,
		Condition: req.Condition,
		Action:    req.Action,
	}

	h.cfg.Policies[req.PolicyIndex].Rules = append(h.cfg.Policies[req.PolicyIndex].Rules, newRule)

	if err := h.saveConfig(); err != nil {
		h.logger.Error("failed to save config", "error", err)
		http.Error(w, `{"error":"failed to save config"}`, http.StatusInternalServerError)
		return
	}

	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// updateRule modifies an existing rule.
func (h *AdminHandler) updateRule(w http.ResponseWriter, r *http.Request) {
	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if req.PolicyIndex < 0 || req.PolicyIndex >= len(h.cfg.Policies) {
		http.Error(w, `{"error":"invalid policy index"}`, http.StatusBadRequest)
		return
	}

	if req.RuleIndex < 0 || req.RuleIndex >= len(h.cfg.Policies[req.PolicyIndex].Rules) {
		http.Error(w, `{"error":"invalid rule index"}`, http.StatusBadRequest)
		return
	}

	h.cfg.Policies[req.PolicyIndex].Rules[req.RuleIndex] = config.RuleConfig{
		Name:      req.Name,
		Condition: req.Condition,
		Action:    req.Action,
	}

	if err := h.saveConfig(); err != nil {
		h.logger.Error("failed to save config", "error", err)
		http.Error(w, `{"error":"failed to save config"}`, http.StatusInternalServerError)
		return
	}

	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// deleteRule removes a rule.
func (h *AdminHandler) deleteRule(w http.ResponseWriter, r *http.Request) {
	var req RuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if req.PolicyIndex < 0 || req.PolicyIndex >= len(h.cfg.Policies) {
		http.Error(w, `{"error":"invalid policy index"}`, http.StatusBadRequest)
		return
	}

	rules := h.cfg.Policies[req.PolicyIndex].Rules
	if req.RuleIndex < 0 || req.RuleIndex >= len(rules) {
		http.Error(w, `{"error":"invalid rule index"}`, http.StatusBadRequest)
		return
	}

	// Remove the rule
	h.cfg.Policies[req.PolicyIndex].Rules = append(rules[:req.RuleIndex], rules[req.RuleIndex+1:]...)

	if err := h.saveConfig(); err != nil {
		h.logger.Error("failed to save config", "error", err)
		http.Error(w, `{"error":"failed to save config"}`, http.StatusInternalServerError)
		return
	}

	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// saveConfig writes the current config to the YAML file.
func (h *AdminHandler) saveConfig() error {
	if h.configPath == "" {
		return nil // No config file to save to
	}

	data, err := yaml.Marshal(h.cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(h.configPath, data, 0644)
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
