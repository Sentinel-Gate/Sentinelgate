package admin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

// dangerousEnvVars is a blocklist of environment variables that could be used
// for code injection when passed to subprocess upstreams.
var dangerousEnvVars = map[string]bool{
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"DYLD_INSERT_LIBRARIES": true, // macOS equivalent of LD_PRELOAD
	"PYTHONPATH":            true,
	"PYTHONSTARTUP":         true,
	"NODE_OPTIONS":          true,
	"NODE_PATH":             true,
	"RUBYOPT":               true,
	"PERL5OPT":              true,
	"PERL5LIB":              true,
	"CLASSPATH":             true,
	"JAVA_TOOL_OPTIONS":     true,
	"_JAVA_OPTIONS":         true,
	"BASH_ENV":              true,
	"ENV":                   true,
	"ZDOTDIR":               true,
	"PROMPT_COMMAND":        true,
	"CGO_LDFLAGS":           true,
	"CGO_CFLAGS":            true,
	"GODEBUG":               true,
}

// SSRFSafeDialer returns a net.Dialer with a Control function that rejects
// connections to private/link-local/loopback IPs at TCP connect time.
// M-5: This MUST be applied unconditionally to ALL upstream HTTP clients,
// not as an opt-in option. The admin-time DNS check in rejectCloudMetadata
// is insufficient alone due to DNS rebinding TOCTOU.
func SSRFSafeDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("SSRF protection: invalid address %q", address)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return nil
			}
			if msg := isBlockedIP(ip); msg != "" {
				return fmt.Errorf("SSRF protection: %s", msg)
			}
			if ip.IsLinkLocalMulticast() {
				return fmt.Errorf("SSRF protection: link-local multicast IP %s blocked", ip)
			}
			return nil
		},
	}
}

// NewSSRFSafeHTTPTransport returns an *http.Transport with the SSRF-safe dialer
// pre-configured. M-5: All upstream HTTP clients MUST use this transport (or
// equivalent) to guarantee connect-time IP blocking against DNS rebinding.
func NewSSRFSafeHTTPTransport() *http.Transport {
	return &http.Transport{
		DialContext:         SSRFSafeDialer().DialContext,
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     90 * time.Second,
	}
}

// validateUpstreamURL validates that an HTTP upstream URL uses only http or https
// and does not point to cloud metadata endpoints (SSRF protection).
// SECURITY: Prevents SSRF via arbitrary URL schemes (gopher://, file://, data://)
// and blocks well-known cloud metadata IPs (169.254.169.254, fd00:ec2::254).
// NOTE (M-5): This is an admin-time check only. Connect-time SSRF protection via
// SSRFSafeDialer/NewSSRFSafeHTTPTransport is ALSO required on all upstream HTTP
// clients to prevent DNS rebinding TOCTOU attacks.
func validateUpstreamURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "invalid URL"
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "only http:// and https:// URL schemes are allowed"
	}
	if parsed.Host == "" {
		return "URL must include a host"
	}
	if msg := rejectCloudMetadata(parsed.Hostname()); msg != "" {
		return msg
	}
	return ""
}

func isBlockedIP(ip net.IP) string {
	if ip.IsLoopback() {
		return "loopback IP addresses are not allowed"
	}
	if ip.IsPrivate() {
		return "private IP addresses are not allowed"
	}
	if ip.IsUnspecified() {
		return "unspecified IP addresses (0.0.0.0/::) are not allowed"
	}
	if ip.IsLinkLocalUnicast() {
		return "link-local IP addresses are not allowed (cloud metadata protection)"
	}
	return ""
}

// rejectCloudMetadata blocks well-known cloud metadata endpoint IPs to prevent
// SSRF attacks that could leak instance credentials or sensitive metadata.
func rejectCloudMetadata(host string) string {
	ip := net.ParseIP(host)
	if ip != nil {
		return isBlockedIP(ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resolver := &net.Resolver{}
	addrs, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return fmt.Sprintf("DNS resolution failed for %s: cannot verify safety", host)
	}
	for _, addr := range addrs {
		resolved := net.ParseIP(addr)
		if resolved == nil {
			continue
		}
		if msg := isBlockedIP(resolved); msg != "" {
			return fmt.Sprintf("hostname %s resolves to blocked IP %s: %s", host, addr, msg)
		}
	}
	return ""
}

// validateEnvVars checks environment variables against a blocklist of
// dangerous vars that could allow code injection in subprocess upstreams.
func validateEnvVars(env map[string]string) string {
	for key := range env {
		if dangerousEnvVars[strings.ToUpper(key)] {
			return "environment variable " + key + " is blocked for security reasons"
		}
	}
	return ""
}

// upstreamRequest is the JSON body for create and update upstream endpoints.
type upstreamRequest struct {
	Name    string            `json:"name"`
	Type    string            `json:"type"`
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	URL     string            `json:"url"`
	Env     map[string]string `json:"env"`
	Enabled *bool             `json:"enabled"` // pointer to distinguish missing from false
}

// upstreamResponse is the JSON representation of an upstream returned by the API.
type upstreamResponse struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Type      string            `json:"type"`
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	URL       string            `json:"url,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Enabled   bool              `json:"enabled"`
	Status    string            `json:"status"`
	LastError string            `json:"last_error,omitempty"`
	ToolCount int               `json:"tool_count"`
	CreatedAt string            `json:"created_at"`
	UpdatedAt string            `json:"updated_at"`
}

// redactEnvValues returns a copy of env with all values masked.
// Keys are preserved so the admin UI can show which variables are set.
func redactEnvValues(env map[string]string) map[string]string {
	if len(env) == 0 {
		return env
	}
	redacted := make(map[string]string, len(env))
	for k := range env {
		redacted[k] = "***"
	}
	return redacted
}

// toUpstreamResponse converts a domain Upstream plus runtime info into an API response.
// SECURITY: Env var values are redacted — only keys are visible in API responses.
func toUpstreamResponse(u *upstream.Upstream, status upstream.ConnectionStatus, lastError string, toolCount int) upstreamResponse {
	return upstreamResponse{
		ID:        u.ID,
		Name:      u.Name,
		Type:      string(u.Type),
		Command:   u.Command,
		Args:      u.Args,
		URL:       u.URL,
		Env:       redactEnvValues(u.Env),
		Enabled:   u.Enabled,
		Status:    string(status),
		LastError: lastError,
		ToolCount: toolCount,
		CreatedAt: u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt: u.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

// handleListUpstreams returns all upstreams with their connection status and tool count.
// GET /admin/api/upstreams
func (h *AdminAPIHandler) handleListUpstreams(w http.ResponseWriter, r *http.Request) {
	if h.upstreamService == nil {
		h.respondError(w, http.StatusServiceUnavailable, "upstream service not configured")
		return
	}
	ctx := r.Context()

	upstreams, err := h.upstreamService.List(ctx)
	if err != nil {
		h.logger.Error("failed to list upstreams", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to list upstreams")
		return
	}

	result := make([]upstreamResponse, 0, len(upstreams))
	for i := range upstreams {
		u := &upstreams[i]

		// Get runtime status from manager.
		status, lastError := h.upstreamManager.Status(u.ID)

		// Get tool count from cache.
		toolCount := 0
		if h.toolCache != nil {
			tools := h.toolCache.GetToolsByUpstream(u.ID)
			toolCount = len(tools)
		}

		result = append(result, toUpstreamResponse(u, status, lastError, toolCount))
	}

	h.respondJSON(w, http.StatusOK, result)
}

// containsPathTraversal checks if a string contains path traversal sequences.
// SECU-08: Prevents path traversal in upstream command and arguments.
// L-6: Also checks URL-encoded variants of ".." to prevent bypass.
func containsPathTraversal(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(s, "..") ||
		strings.Contains(lower, "%2e%2e") ||
		strings.Contains(lower, "%2e.") ||
		strings.Contains(lower, ".%2e")
}

// validateCommandSafety checks command and args for path traversal and empty commands.
// Returns an error message suitable for API response, or empty string if valid.
func validateCommandSafety(upstreamType upstream.UpstreamType, command string, args []string) string {
	// SECU-08: Reject path traversal in command.
	if containsPathTraversal(command) {
		return "path traversal detected in command"
	}
	// SECU-08: Reject path traversal in arguments.
	for _, arg := range args {
		if containsPathTraversal(arg) {
			return "path traversal detected in arguments"
		}
	}
	// Stdio upstreams must have a non-empty command.
	if upstreamType == upstream.UpstreamTypeStdio && strings.TrimSpace(command) == "" {
		return "command is required for stdio upstreams"
	}
	return ""
}

// handleCreateUpstream creates a new upstream, optionally starts it and discovers tools.
// POST /admin/api/upstreams
func (h *AdminAPIHandler) handleCreateUpstream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req upstreamRequest
	if !h.readJSONBody(w, r, &req) {
		return
	}

	// Validate required fields at API level.
	if strings.TrimSpace(req.Name) == "" {
		h.respondError(w, http.StatusBadRequest, "name is required")
		return
	}

	upstreamType := upstream.UpstreamType(req.Type)
	if upstreamType != upstream.UpstreamTypeStdio && upstreamType != upstream.UpstreamTypeHTTP {
		h.respondError(w, http.StatusBadRequest, "type must be \"stdio\" or \"http\"")
		return
	}

	// SECU-08: Validate command and args for path traversal.
	if msg := validateCommandSafety(upstreamType, req.Command, req.Args); msg != "" {
		h.respondError(w, http.StatusBadRequest, msg)
		return
	}

	// SECU-09: Validate URL scheme (http/https only, prevents SSRF).
	if upstreamType == upstream.UpstreamTypeHTTP {
		if msg := validateUpstreamURL(req.URL); msg != "" {
			h.respondError(w, http.StatusBadRequest, msg)
			return
		}
	}

	// SECU-10: Block dangerous environment variables.
	if msg := validateEnvVars(req.Env); msg != "" {
		h.respondError(w, http.StatusBadRequest, msg)
		return
	}

	// Default enabled to true if not specified.
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	u := &upstream.Upstream{
		Name:    strings.TrimSpace(req.Name),
		Type:    upstreamType,
		Command: req.Command,
		Args:    req.Args,
		URL:     req.URL,
		Env:     req.Env,
		Enabled: enabled,
	}

	created, err := h.upstreamService.Add(ctx, u)
	if err != nil {
		if errors.Is(err, upstream.ErrDuplicateUpstreamName) {
			h.respondError(w, http.StatusConflict, "upstream name already exists")
			return
		}
		h.logger.Error("failed to create upstream", "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to create upstream")
		return
	}

	// If enabled, attempt to start connection and discover tools (non-fatal).
	if enabled && h.upstreamManager != nil {
		if startErr := h.upstreamManager.Start(ctx, created.ID); startErr != nil {
			h.logger.Warn("failed to start upstream after create", "id", created.ID, "error", startErr)
		}
	}
	if enabled && h.discoveryService != nil {
		if _, discoverErr := h.discoveryService.DiscoverFromUpstream(ctx, created.ID); discoverErr != nil {
			h.logger.Warn("failed to discover tools after create", "id", created.ID, "error", discoverErr)
		}
		// Auto-update baseline to include the new upstream's tools so the admin
		// does not need to manually re-capture after adding a server.
		if h.toolSecurityService != nil {
			if _, baseErr := h.toolSecurityService.CaptureBaseline(ctx); baseErr != nil {
				h.logger.Warn("failed to auto-capture baseline after upstream create", "id", created.ID, "error", baseErr)
			}
		}
	}

	// Build response with runtime info.
	var status upstream.ConnectionStatus
	var lastError string
	if h.upstreamManager != nil {
		status, lastError = h.upstreamManager.Status(created.ID)
	}
	toolCount := 0
	if h.toolCache != nil {
		toolCount = len(h.toolCache.GetToolsByUpstream(created.ID))
	}

	h.respondJSON(w, http.StatusCreated, toUpstreamResponse(created, status, lastError, toolCount))
}

// handleUpdateUpstream updates an existing upstream's configuration.
// PUT /admin/api/upstreams/{id}
func (h *AdminAPIHandler) handleUpdateUpstream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := h.pathParam(r, "id")

	var req upstreamRequest
	if !h.readJSONBody(w, r, &req) {
		return
	}

	// Get existing upstream to preserve immutable fields.
	existing, err := h.upstreamService.Get(ctx, id)
	if err != nil {
		if errors.Is(err, upstream.ErrUpstreamNotFound) {
			h.respondError(w, http.StatusNotFound, "upstream not found")
			return
		}
		h.logger.Error("failed to get upstream", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get upstream")
		return
	}

	// Build updated upstream, preserving type (immutable).
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = existing.Name
	}

	// Resolve command/args: use request values if provided, else preserve existing.
	command := req.Command
	if command == "" {
		command = existing.Command
	}
	args := req.Args
	if args == nil {
		args = existing.Args
	}

	// SECU-08: Validate command and args for path traversal.
	if msg := validateCommandSafety(existing.Type, command, args); msg != "" {
		h.respondError(w, http.StatusBadRequest, msg)
		return
	}

	// SECU-09: Validate URL scheme on update too.
	if existing.Type == upstream.UpstreamTypeHTTP && req.URL != "" {
		if msg := validateUpstreamURL(req.URL); msg != "" {
			h.respondError(w, http.StatusBadRequest, msg)
			return
		}
	}

	// SECU-10: Block dangerous environment variables on update.
	if req.Env != nil {
		if msg := validateEnvVars(req.Env); msg != "" {
			h.respondError(w, http.StatusBadRequest, msg)
			return
		}
	}

	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	env := req.Env
	if env == nil {
		env = existing.Env
	} else if existing.Env != nil {
		// Restore redacted values: the API returns "***" for env values
		// (see redactEnvValues). When the frontend sends "***" back on edit,
		// preserve the original value to prevent data corruption.
		merged := make(map[string]string, len(env))
		for k, v := range env {
			if v == "***" {
				if orig, ok := existing.Env[k]; ok {
					merged[k] = orig
					continue
				}
			}
			merged[k] = v
		}
		env = merged
	}

	u := &upstream.Upstream{
		Name:    name,
		Type:    existing.Type, // Type is immutable.
		Command: command,
		Args:    args,
		URL:     req.URL,
		Env:     env,
		Enabled: enabled,
	}

	// If url not provided, preserve existing value.
	if u.URL == "" {
		u.URL = existing.URL
	}

	updated, err := h.upstreamService.Update(ctx, id, u)
	if err != nil {
		if errors.Is(err, upstream.ErrUpstreamNotFound) {
			h.respondError(w, http.StatusNotFound, "upstream not found")
			return
		}
		if errors.Is(err, upstream.ErrDuplicateUpstreamName) {
			h.respondError(w, http.StatusConflict, "upstream name already exists")
			return
		}
		h.logger.Error("failed to update upstream", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to update upstream")
		return
	}

	// Restart the upstream so the new config takes effect immediately.
	if h.upstreamManager != nil {
		if err := h.upstreamManager.Restart(ctx, id); err != nil {
			h.logger.Warn("failed to restart upstream after update", "id", id, "error", err)
		}
	}

	// Re-discover tools after restart (non-fatal).
	if h.discoveryService != nil {
		if _, discoverErr := h.discoveryService.DiscoverFromUpstream(ctx, id); discoverErr != nil {
			h.logger.Warn("failed to re-discover tools after update", "id", id, "error", discoverErr)
		}
		if h.toolSecurityService != nil {
			h.toolSecurityService.CheckIntegrityAndEmit(ctx)
		}
	}

	var status upstream.ConnectionStatus
	var lastError string
	if h.upstreamManager != nil {
		status, lastError = h.upstreamManager.Status(id)
	}
	toolCount := 0
	if h.toolCache != nil {
		toolCount = len(h.toolCache.GetToolsByUpstream(id))
	}

	h.respondJSON(w, http.StatusOK, toUpstreamResponse(updated, status, lastError, toolCount))
}

// handleDeleteUpstream stops and removes an upstream.
// DELETE /admin/api/upstreams/{id}
func (h *AdminAPIHandler) handleDeleteUpstream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := h.pathParam(r, "id")

	// Check if upstream exists. If already gone, return 204 for idempotency.
	if _, err := h.upstreamService.Get(ctx, id); err != nil {
		if errors.Is(err, upstream.ErrUpstreamNotFound) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.logger.Error("failed to get upstream for delete", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get upstream")
		return
	}

	// Stop connection (log error but continue with deletion).
	if h.upstreamManager != nil {
		if err := h.upstreamManager.Stop(id); err != nil {
			h.logger.Warn("failed to stop upstream during delete", "id", id, "error", err)
		}
	}

	// Clear tool cache for this upstream and invalidate stale conflict data.
	if h.toolCache != nil {
		h.toolCache.RemoveUpstream(id)
		h.toolCache.ClearConflicts()
	}

	// Notify connected clients about tool list change.
	if h.toolChangeNotifier != nil {
		h.toolChangeNotifier.NotifyToolsChanged()
	}

	// Delete from store.
	if err := h.upstreamService.Delete(ctx, id); err != nil {
		if errors.Is(err, upstream.ErrUpstreamNotFound) {
			// Race: deleted between Get and Delete; treat as success.
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.logger.Error("failed to delete upstream", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to delete upstream")
		return
	}

	// Auto-update baseline to exclude the removed upstream's tools.
	if h.toolSecurityService != nil {
		if _, baseErr := h.toolSecurityService.CaptureBaseline(ctx); baseErr != nil {
			// CaptureBaseline rejects empty caches by design. If no tools remain
			// (last upstream deleted), clear the baseline to prevent stale drift reports.
			if h.toolCache != nil && len(h.toolCache.GetAllTools()) == 0 {
				if clearErr := h.toolSecurityService.ClearBaseline(); clearErr != nil {
					h.logger.Warn("failed to clear baseline after last upstream delete", "id", id, "error", clearErr)
				}
			} else {
				h.logger.Warn("failed to auto-capture baseline after upstream delete", "id", id, "error", baseErr)
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleRestartUpstream restarts an upstream and optionally re-discovers tools.
// POST /admin/api/upstreams/{id}/restart
func (h *AdminAPIHandler) handleRestartUpstream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := h.pathParam(r, "id")

	// Verify upstream exists.
	if _, err := h.upstreamService.Get(ctx, id); err != nil {
		if errors.Is(err, upstream.ErrUpstreamNotFound) {
			h.respondError(w, http.StatusNotFound, "upstream not found")
			return
		}
		h.logger.Error("failed to get upstream for restart", "id", id, "error", err)
		h.respondError(w, http.StatusInternalServerError, "failed to get upstream")
		return
	}

	// Restart the upstream connection.
	if h.upstreamManager != nil {
		if err := h.upstreamManager.Restart(ctx, id); err != nil {
			h.logger.Error("failed to restart upstream", "id", id, "error", err)
			h.respondError(w, http.StatusInternalServerError, "failed to restart upstream")
			return
		}
	}

	// Re-discover tools (non-fatal).
	if h.discoveryService != nil {
		if _, discoverErr := h.discoveryService.DiscoverFromUpstream(ctx, id); discoverErr != nil {
			h.logger.Warn("failed to re-discover tools after restart", "id", id, "error", discoverErr)
		}
		// Check for tool drift after restart — a restarted upstream may have
		// changed its tool set (update, compromise, etc.).
		if h.toolSecurityService != nil {
			h.toolSecurityService.CheckIntegrityAndEmit(ctx)
		}
	}

	// Get new status.
	var status upstream.ConnectionStatus
	var lastError string
	if h.upstreamManager != nil {
		status, lastError = h.upstreamManager.Status(id)
	}

	h.respondJSON(w, http.StatusOK, map[string]string{
		"status":     string(status),
		"last_error": lastError,
		"message":    "upstream restarted",
	})
}
