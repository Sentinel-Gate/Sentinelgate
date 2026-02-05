// Package admin provides a web UI for Sentinel Gate OSS.
// Allows viewing and editing policies and rules.
package admin

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
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

//go:embed static/*
var staticFS embed.FS

const adminCookieName = "sentinel_admin_key"

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

	// Static files (no auth)
	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /admin/static/", http.StripPrefix("/admin/static/", http.FileServer(http.FS(staticSub))))

	// Login/logout (no auth)
	mux.HandleFunc("GET /admin/login", h.loginPage)
	mux.HandleFunc("POST /admin/login", h.loginSubmit)
	mux.HandleFunc("GET /admin/logout", h.logout)

	// Dashboard (auth required)
	mux.HandleFunc("GET /admin", h.requireAuth(h.dashboardPage))
	mux.HandleFunc("GET /admin/", h.requireAuth(h.dashboardPage))

	// API endpoints (auth required)
	mux.HandleFunc("GET /admin/api/rules", h.requireAuth(h.listRules))
	mux.HandleFunc("POST /admin/api/rules", h.requireAuth(h.createRule))
	mux.HandleFunc("PUT /admin/api/rules", h.requireAuth(h.updateRule))
	mux.HandleFunc("DELETE /admin/api/rules", h.requireAuth(h.deleteRule))

	return mux
}

// requireAuth wraps a handler with authentication check.
func (h *AdminHandler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.isAuthenticated(r) {
			if strings.HasPrefix(r.URL.Path, "/admin/api/") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

// isAuthenticated checks if the request has valid authentication.
func (h *AdminHandler) isAuthenticated(r *http.Request) bool {
	if h.cfg.DevMode {
		cookie, err := r.Cookie(adminCookieName)
		return err == nil && cookie.Value != ""
	}

	cookie, err := r.Cookie(adminCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	keyHash := hashKey(cookie.Value)
	for _, apiKey := range h.cfg.Auth.APIKeys {
		if strings.TrimPrefix(apiKey.KeyHash, "sha256:") == keyHash {
			return true
		}
	}
	return false
}

// loginPage renders the login form.
func (h *AdminHandler) loginPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"DevMode": h.cfg.DevMode,
		"Error":   "",
	}
	h.tmpl.ExecuteTemplate(w, "login", data)
}

// loginSubmit handles login form submission.
func (h *AdminHandler) loginSubmit(w http.ResponseWriter, r *http.Request) {
	apiKey := r.FormValue("api_key")

	if apiKey == "" {
		data := map[string]interface{}{
			"DevMode": h.cfg.DevMode,
			"Error":   "API key is required",
		}
		h.tmpl.ExecuteTemplate(w, "login", data)
		return
	}

	valid := false
	if h.cfg.DevMode {
		valid = true
	} else {
		keyHash := hashKey(apiKey)
		for _, k := range h.cfg.Auth.APIKeys {
			if strings.TrimPrefix(k.KeyHash, "sha256:") == keyHash {
				valid = true
				break
			}
		}
	}

	if !valid {
		data := map[string]interface{}{
			"DevMode": h.cfg.DevMode,
			"Error":   "Invalid API key",
		}
		h.tmpl.ExecuteTemplate(w, "login", data)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    apiKey,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// logout clears the auth cookie.
func (h *AdminHandler) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

// dashboardPage renders the main dashboard.
func (h *AdminHandler) dashboardPage(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	upstream := h.cfg.Upstream.HTTP
	if upstream == "" && h.cfg.Upstream.Command != "" {
		upstream = h.cfg.Upstream.Command + " (stdio)"
	}

	ruleCount := 0
	for _, p := range h.cfg.Policies {
		ruleCount += len(p.Rules)
	}

	auditOutput := h.cfg.Audit.Output
	if auditOutput == "" {
		auditOutput = "stdout"
	}

	h.logMu.RLock()
	logs := make([]AuditEntry, len(h.logBuffer))
	copy(logs, h.logBuffer)
	h.logMu.RUnlock()

	data := map[string]interface{}{
		"Upstream":         upstream,
		"PolicyCount":      len(h.cfg.Policies),
		"RuleCount":        ruleCount,
		"Policies":         h.cfg.Policies,
		"ListenAddr":       h.cfg.Server.HTTPAddr,
		"DevMode":          h.cfg.DevMode,
		"RateLimitEnabled": h.cfg.RateLimit.Enabled,
		"AuditOutput":      auditOutput,
		"Logs":             logs,
		"ConfigPath":       h.configPath,
	}

	h.tmpl.ExecuteTemplate(w, "dashboard", data)
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
	json.NewEncoder(w).Encode(h.cfg.Policies)
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
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

// hashKey returns the SHA-256 hash of a key as hex string.
func hashKey(key string) string {
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])
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
