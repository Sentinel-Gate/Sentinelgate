// Package proxy contains the core domain logic for the MCP proxy.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// JSON-RPC error codes used by the router.
const (
	// ErrCodeMethodNotFound is returned when a tool is not found in any upstream.
	ErrCodeMethodNotFound int64 = -32601
	// ErrCodeInternal is returned when an upstream connection fails.
	ErrCodeInternal int64 = -32603
	// ErrCodeInvalidParams is returned when the client sends invalid parameters.
	ErrCodeInvalidParams int64 = -32602
	// ErrCodeNoUpstreams is returned when no upstreams are available (503-equivalent).
	// L-13: -32000 is the start of the JSON-RPC server error reserved range (-32000 to -32099);
	// acceptable for "no upstreams" error as server-defined errors are intended for this range.
	ErrCodeNoUpstreams int64 = -32000

	// mcpProtocolVersion is the MCP protocol version advertised by the proxy.
	mcpProtocolVersion = "2025-11-25"
	// serverVersion is the SentinelGate server version.
	serverVersion = "1.1.0"
)

// RoutableTool represents a tool that can be routed to a specific upstream.
// This is a minimal struct with just the fields the router needs, avoiding
// circular imports with the upstream package's DiscoveredTool type.
type RoutableTool struct {
	// Name is the tool's resolved name (may include namespace prefix like "desktop/read_file").
	Name string
	// OriginalName is the bare tool name as registered by the upstream (e.g. "read_file").
	// Used when forwarding to upstream which doesn't know about namespacing.
	OriginalName string
	// UpstreamID identifies which upstream owns this tool.
	UpstreamID string
	// UpstreamName is the human-readable name of the upstream.
	UpstreamName string
	// Description is the human-readable tool description.
	Description string
	// InputSchema is the JSON Schema for the tool's input parameters.
	InputSchema json.RawMessage
}

// ToolCacheReader provides read access to the shared tool cache.
// The ToolCache from the upstream package will satisfy this interface.
type ToolCacheReader interface {
	// GetTool looks up a tool by resolved name. Returns the tool and true if found.
	GetTool(name string) (*RoutableTool, bool)
	// GetAllTools returns all discovered tools across all upstreams with resolved names.
	GetAllTools() []*RoutableTool
	// IsAmbiguous checks if a bare tool name is shared across multiple upstreams.
	// Returns true and a list of namespaced alternatives if ambiguous.
	IsAmbiguous(name string) (bool, []string)
}

// UpstreamConnectionProvider provides access to upstream connections.
// The UpstreamManager will satisfy this interface.
type UpstreamConnectionProvider interface {
	// GetConnection returns the stdin writer and stdout reader for an upstream.
	GetConnection(upstreamID string) (io.WriteCloser, <-chan []byte, error)
	// AllConnected returns true if at least one upstream is connected.
	AllConnected() bool
}

// NamespaceFilter optionally filters tools based on identity roles.
// Returns true if the tool should be visible to the given roles.
type NamespaceFilter interface {
	IsToolVisible(toolName string, roles []string) bool
}

// NotificationForwarder receives upstream notifications that should be sent
// to the client. Implementations must be safe for concurrent use.
type NotificationForwarder interface {
	// ForwardNotification sends a raw JSON-RPC notification to the client.
	// The data is a complete JSON-RPC notification (no trailing newline).
	ForwardNotification(data []byte)
}

// UpstreamRouter routes MCP messages to the appropriate upstream based on
// tool name lookup in the shared ToolCache. It is the innermost interceptor
// in the chain for multi-upstream mode.
type UpstreamRouter struct {
	toolCache       ToolCacheReader
	manager         UpstreamConnectionProvider
	nsMu              sync.RWMutex
	namespaceFilter   NamespaceFilter
	clientFramework   string     // legacy: last-seen framework (for stats)
	clientFrameworks  sync.Map   // session ID → framework string (per-session)
	logger          *slog.Logger
	ioMutexes sync.Map // per-upstream ID → *sync.Mutex
	notifMu            sync.RWMutex
	notificationFwd    NotificationForwarder
}

// CleanupUpstream removes the per-upstream I/O mutex entry for the given ID.
// Call this when an upstream is permanently removed to prevent unbounded growth.
func (r *UpstreamRouter) CleanupUpstream(upstreamID string) {
	r.ioMutexes.Delete(upstreamID)
}

// CleanupSession removes the per-session framework entry for the given session ID.
// Call this when a session is terminated or expired to prevent unbounded growth.
func (r *UpstreamRouter) CleanupSession(sessionID string) {
	r.clientFrameworks.Delete(sessionID)
}

// NewUpstreamRouter creates a new UpstreamRouter.
func NewUpstreamRouter(cache ToolCacheReader, manager UpstreamConnectionProvider, logger *slog.Logger) *UpstreamRouter {
	return &UpstreamRouter{
		toolCache: cache,
		manager:   manager,
		logger:    logger,
	}
}

// SetNotificationForwarder sets the callback used to forward upstream notifications
// (e.g. notifications/progress, notifications/message) to the connected client.
// When nil (default), upstream notifications are silently dropped.
func (r *UpstreamRouter) SetNotificationForwarder(fwd NotificationForwarder) {
	r.notifMu.Lock()
	r.notificationFwd = fwd
	r.notifMu.Unlock()
}

// getNotificationForwarder returns the current notification forwarder under read lock.
func (r *UpstreamRouter) getNotificationForwarder() NotificationForwarder {
	r.notifMu.RLock()
	defer r.notifMu.RUnlock()
	return r.notificationFwd
}

// SetNamespaceFilter sets an optional filter that restricts tool visibility per role.
// When set, tools/list responses are filtered based on the caller's roles.
func (r *UpstreamRouter) SetNamespaceFilter(filter NamespaceFilter) {
	r.nsMu.Lock()
	r.namespaceFilter = filter
	r.nsMu.Unlock()
}

// getNamespaceFilter returns the current namespace filter under read lock.
func (r *UpstreamRouter) getNamespaceFilter() NamespaceFilter {
	r.nsMu.RLock()
	defer r.nsMu.RUnlock()
	return r.namespaceFilter
}

// Intercept routes the message to the appropriate upstream based on method type.
// - tools/list: aggregates tools from all upstreams via the ToolCache
// - tools/call: routes to the correct upstream based on tool name lookup
// - other methods: forwards to the first connected upstream (primary)
func (r *UpstreamRouter) Intercept(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Server-to-client messages (responses) pass through without routing.
	// Only client-to-server requests need to be routed to upstreams.
	if msg.Direction == mcp.ServerToClient {
		return msg, nil
	}

	method := msg.Method()

	// Guard: never forward notifications (no "id") to upstreams — except
	// notifications/cancelled which must reach the upstream handling the request.
	// A notification tools/call would block the per-upstream mutex for 30s
	// waiting for a response that never arrives (DoS vector).
	// Per JSON-RPC 2.0 Section 4.1: "The Server MUST NOT reply to a Notification."
	// Return nil, nil to silently drop; proxy_service handles this correctly.
	//
	// M-22: Use rawIDFromBytes() instead of msg.RawID() for notification detection.
	// RawID() caches its result via sync.Once; if an upstream interceptor mutates
	// msg.Raw after the first call, the cached value would be stale. Checking raw
	// bytes directly avoids this correctness hazard. msg.Raw MUST NOT be mutated
	// after construction — this is the immutability contract for Message.Raw.
	if rawIDFromBytes(msg.Raw) == nil && msg.Direction == mcp.ClientToServer {
		if method == "notifications/cancelled" {
			r.forwardCancelledNotification(ctx, msg)
		}
		return nil, nil
	}

	if method == "initialize" {
		return r.handleInitialize(msg)
	}

	// M-40: Handle notifications/initialized locally — exempt from AllConnected().
	// M-39: If sent as a request (with id), reject per spec.
	// L-31: "initialized" alias implemented for compatibility with clients that omit "notifications/" prefix.
	if method == "notifications/initialized" || method == "initialized" {
		if msg.RawID() != nil {
			return r.buildErrorResponse(msg, -32600, "Invalid Request: notifications/initialized must be sent as notification (no id)"), nil
		}
		return nil, nil
	}

	switch method {
	case "tools/list":
		return r.handleToolsList(msg)
	case "ping":
		return r.buildResultResponse(msg, struct{}{})
	default:
		if !r.manager.AllConnected() {
			r.logger.Warn("no upstreams available")
			return r.buildErrorResponse(msg, ErrCodeNoUpstreams, "No upstreams available"), nil
		}
		if method == "tools/call" {
			return r.handleToolsCall(ctx, msg)
		}
		return r.handleForward(ctx, msg)
	}
}

// handleToolsList aggregates tools from all upstreams into a unified response.
// When a NamespaceFilter is set, tools are filtered based on the caller's roles.
func (r *UpstreamRouter) handleToolsList(msg *mcp.Message) (*mcp.Message, error) {
	allTools := r.toolCache.GetAllTools()

	// Sort tools by name for deterministic ordering.
	sort.SliceStable(allTools, func(i, j int) bool {
		return allTools[i].Name < allTools[j].Name
	})

	// Extract caller roles for namespace filtering.
	var callerRoles []string
	if msg.Session != nil {
		for _, role := range msg.Session.Roles {
			callerRoles = append(callerRoles, string(role))
		}
	}


	// Build the tools array for the response, applying namespace filter.
	nsFilter := r.getNamespaceFilter()
	tools := make([]toolEntry, 0, len(allTools))
	for _, t := range allTools {
		// Namespace isolation: skip tools not visible to caller's roles.
		// When namespace filter is active and caller has no roles, deny all tools
		// (principle of least privilege — no roles = no visibility).
		if nsFilter != nil {
			if len(callerRoles) == 0 || !nsFilter.IsToolVisible(t.Name, callerRoles) {
				continue
			}
		}

		entry := toolEntry{
			Name:        t.Name,
			Description: t.Description,
		}
		if t.InputSchema != nil {
			entry.InputSchema = t.InputSchema
		}
		tools = append(tools, entry)
	}

	// Build the JSON-RPC response.
	result := toolsListResult{Tools: tools}

	return r.buildResultResponse(msg, result)
}

// handleToolsCall routes a tools/call request to the upstream that owns the tool.
func (r *UpstreamRouter) handleToolsCall(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// Extract tool name from request params.
	toolName := r.extractToolName(msg)
	if toolName == "" {
		r.logger.Warn("tools/call missing tool name")
		return r.buildErrorResponse(msg, ErrCodeMethodNotFound, "Tool not found: (empty name)"), nil
	}

	// L-9: Sanitize toolName (length limit + character filter) before including
	// in JSON-RPC error messages. Defense-in-depth independent of ValidationInterceptor.
	safeName := sanitizeToolName(toolName)

	// Look up the tool in the cache by resolved name.
	tool, found := r.toolCache.GetTool(toolName)
	if !found {
		// Check if the bare name is ambiguous (shared across upstreams).
		if ambig, suggestions := r.toolCache.IsAmbiguous(toolName); ambig {
			// Filter suggestions through namespace filter to avoid leaking hidden tools.
			nsFilter := r.getNamespaceFilter()
			if nsFilter != nil {
				var callerRoles []string
				if msg.Session != nil {
					for _, role := range msg.Session.Roles {
						callerRoles = append(callerRoles, string(role))
					}
				}
				visible := suggestions[:0:0]
				for _, s := range suggestions {
					if nsFilter.IsToolVisible(s, callerRoles) {
						visible = append(visible, s)
					}
				}
				suggestions = visible
			}
			if len(suggestions) > 0 {
				hint := fmt.Sprintf("Tool '%s' is ambiguous. Use one of: %s",
					safeName, strings.Join(suggestions, ", "))
				return r.buildErrorResponse(msg, ErrCodeMethodNotFound, hint), nil
			}
		}
		r.logger.Warn("tool not found", "tool", safeName)
		return r.buildErrorResponse(msg, ErrCodeMethodNotFound, fmt.Sprintf("Tool not found: %s", safeName)), nil
	}

	// Namespace isolation check: hidden tools cannot be called directly.
	nsFilter := r.getNamespaceFilter()
	if nsFilter != nil {
		var callerRoles []string
		if msg.Session != nil {
			for _, role := range msg.Session.Roles {
				callerRoles = append(callerRoles, string(role))
			}
		}
		if len(callerRoles) == 0 || !nsFilter.IsToolVisible(toolName, callerRoles) {
			return r.buildErrorResponse(msg, ErrCodeMethodNotFound, fmt.Sprintf("Tool not found: %s", safeName)), nil
		}
	}

	r.logger.Debug("routing tools/call", "tool", toolName, "upstream", tool.UpstreamID)

	// If the resolved name differs from the original bare name (i.e. it's namespaced),
	// rewrite the tool name in the message before forwarding to the upstream.
	// The upstream doesn't know about namespacing and expects the bare name.
	forwardMsg := msg
	if tool.OriginalName != "" && tool.OriginalName != toolName {
		rewritten, err := rewriteToolNameInMessage(msg.Raw, tool.OriginalName)
		if err != nil {
			r.logger.Error("failed to rewrite tool name for forwarding", "error", err)
			return r.buildErrorResponse(msg, ErrCodeInternal, "Internal routing error"), nil
		}
		forwardMsg = &mcp.Message{
			Raw:       rewritten,
			Direction: msg.Direction,
			Timestamp: msg.Timestamp,
			Session:   msg.Session,
			APIKey:    msg.APIKey,
		}
	}

	resp, err := r.forwardToUpstream(ctx, tool.UpstreamID, forwardMsg)
	if err != nil {
		r.logger.Error("upstream forward failed", "upstream", tool.UpstreamID, "error", err)
		// M-16: Do not expose upstream ID to clients; it is already logged server-side.
		return r.buildErrorResponse(msg, ErrCodeInternal, "Upstream unavailable"), nil
	}
	return resp, nil
}

// ClientFramework returns the last-seen client framework name (for backward compat / stats).
func (r *UpstreamRouter) ClientFramework() string {
	r.nsMu.RLock()
	defer r.nsMu.RUnlock()
	return r.clientFramework
}

// ClientFrameworkForSession returns the framework for a specific session ID.
// Falls back to the global (last-seen) framework if no per-session entry exists.
func (r *UpstreamRouter) ClientFrameworkForSession(sessionID string) string {
	if sessionID != "" {
		if fw, ok := r.clientFrameworks.Load(sessionID); ok {
			return fw.(string)
		}
	}
	return r.ClientFramework()
}

// handleInitialize responds to the MCP initialize handshake directly.
// The proxy advertises its own capabilities (tools) without forwarding to upstreams.
func (r *UpstreamRouter) handleInitialize(msg *mcp.Message) (*mcp.Message, error) {
	r.logger.Debug("handling initialize locally")

	params := msg.ParseParams()

	// M-20: Validate required initialize params per MCP spec.
	if params == nil {
		return r.buildErrorResponse(msg, ErrCodeInvalidParams, "Invalid params: protocolVersion is required"), nil
	}
	if _, ok := params["protocolVersion"]; !ok {
		return r.buildErrorResponse(msg, ErrCodeInvalidParams, "Invalid params: protocolVersion is required"), nil
	}
	if _, ok := params["clientInfo"]; !ok {
		return r.buildErrorResponse(msg, ErrCodeInvalidParams, "Invalid params: clientInfo is required"), nil
	}

	// L-27: Per MCP spec, respond with the server's supported protocolVersion instead
	// of hard-rejecting mismatched versions. The client can then decide whether to
	// continue or disconnect based on the version in the response.
	if pv, ok := params["protocolVersion"].(string); ok && pv != mcpProtocolVersion {
		r.logger.Info("client requested unsupported protocol version, responding with supported version",
			"requested", pv, "supported", mcpProtocolVersion)
	}
	if clientInfo, ok := params["clientInfo"].(map[string]interface{}); ok {
		if name, ok := clientInfo["name"].(string); ok && name != "" {
			// M-3: Sanitize clientFramework from untrusted input.
			sanitized := sanitizeClientFramework(name)
			r.nsMu.Lock()
			r.clientFramework = sanitized
			r.nsMu.Unlock()
			// Store per-session framework for accurate audit attribution.
			if msg.Session != nil && msg.Session.ID != "" {
				r.clientFrameworks.Store(msg.Session.ID, sanitized)
			}
		}
	}

	result := map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities": map[string]any{
			"tools": map[string]any{
				"listChanged": true,
			},
		},
		"serverInfo": map[string]any{
			"name":    "sentinel-gate",
			"version": serverVersion,
		},
	}

	return r.buildResultResponse(msg, result)
}

// forwardableMethodAllowlist defines which non-tool methods may be forwarded to upstreams.
// M-16: Prevents arbitrary method forwarding that could reach unintended upstream endpoints.
var forwardableMethodAllowlist = map[string]bool{
	"resources/list":           true,
	"resources/read":           true,
	"resources/subscribe":      true,
	"resources/unsubscribe":    true,
	"resources/templates/list": true, // H-12: MCP resource templates
	"prompts/list":             true,
	"prompts/get":              true,
	"completion/complete":      true,
	"logging/setLevel":         true,
}

// handleForward forwards non-tool messages to the first available upstream.
func (r *UpstreamRouter) handleForward(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	// M-16: Only forward methods on the allowlist to prevent unvalidated forwarding.
	method := msg.Method()
	if !forwardableMethodAllowlist[method] {
		r.logger.Warn("rejecting non-allowlisted method for forwarding", "method", method)
		return r.buildErrorResponse(msg, ErrCodeMethodNotFound, fmt.Sprintf("Method not found: %s", method)), nil
	}
	r.logger.Debug("forwarding message to upstream", "method", method)

	allTools := r.toolCache.GetAllTools()
	if len(allTools) > 0 {
		seen := make(map[string]bool)
		var orderedIDs []string
		sort.SliceStable(allTools, func(i, j int) bool {
			return allTools[i].UpstreamID < allTools[j].UpstreamID
		})
		for _, t := range allTools {
			if !seen[t.UpstreamID] {
				seen[t.UpstreamID] = true
				orderedIDs = append(orderedIDs, t.UpstreamID)
			}
		}

		for _, upstreamID := range orderedIDs {
			resp, err := r.forwardToUpstream(ctx, upstreamID, msg)
			if err != nil {
				r.logger.Error("upstream forward failed", "upstream", upstreamID, "error", err)
				continue
			}
			if r.isMethodNotFoundResponse(resp) {
				r.logger.Debug("upstream returned method-not-found, trying next", "upstream", upstreamID, "method", msg.Method())
				continue
			}
			return resp, nil
		}
	}

	resp, err := r.forwardToUpstream(ctx, "primary", msg)
	if err != nil {
		r.logger.Error("no upstream available for forwarding", "method", msg.Method(), "error", err)
		return r.buildErrorResponse(msg, ErrCodeNoUpstreams, "No upstream available"), nil
	}

	return resp, nil
}

func (r *UpstreamRouter) isMethodNotFoundResponse(msg *mcp.Message) bool {
	if msg == nil || len(msg.Raw) == 0 {
		return false
	}
	var envelope struct {
		Error *struct {
			Code int64 `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(msg.Raw, &envelope) != nil {
		return false
	}
	return envelope.Error != nil && envelope.Error.Code == ErrCodeMethodNotFound
}

// forwardCancelledNotification forwards a notifications/cancelled to all connected upstreams.
// The notification includes a requestId param identifying the request to cancel.
// Because we don't track which upstream owns a given request ID, we broadcast to all.
// This is fire-and-forget: errors are logged but not propagated.
func (r *UpstreamRouter) forwardCancelledNotification(ctx context.Context, msg *mcp.Message) {
	data := msg.Raw
	if len(data) == 0 {
		return
	}
	if data[len(data)-1] != '\n' {
		dataCopy := make([]byte, len(data), len(data)+1)
		copy(dataCopy, data)
		dataCopy = append(dataCopy, '\n')
		data = dataCopy
	}

	// Collect unique upstream IDs from the tool cache.
	seen := make(map[string]bool)
	for _, t := range r.toolCache.GetAllTools() {
		if seen[t.UpstreamID] {
			continue
		}
		seen[t.UpstreamID] = true
		writer, _, err := r.manager.GetConnection(t.UpstreamID)
		if err != nil {
			r.logger.Debug("skipping cancelled notification for unavailable upstream", "upstream", t.UpstreamID)
			continue
		}
		// M-4: Acquire per-upstream I/O mutex to prevent interleaved writes.
		muI, _ := r.ioMutexes.LoadOrStore(t.UpstreamID, &sync.Mutex{})
		mu := muI.(*sync.Mutex)
		mu.Lock()
		_, writeErr := writer.Write(data)
		mu.Unlock()
		if writeErr != nil {
			r.logger.Warn("failed to forward notifications/cancelled", "upstream", t.UpstreamID, "error", writeErr)
		} else {
			r.logger.Debug("forwarded notifications/cancelled", "upstream", t.UpstreamID)
		}
	}
}

// forwardToUpstream writes the raw message to the upstream's stdin and reads the response.
// It serializes access per upstream (using ioMutexes) so that concurrent goroutines
// sharing the same stdio pipes don't get each other's responses. After reading, it
// remaps the response ID to match the client's original request ID.
//
// GetConnection is called inside the critical section to prevent using a stale
// lineCh after a reconnect swaps the channel reference (H-9).
//
// Upstream notifications (messages with "method" and no "id", e.g.
// notifications/progress) are forwarded to the client via the
// NotificationForwarder if one is set (H-4). Context cancellation unblocks
// the select loop immediately instead of waiting up to 30s (H-5).
func (r *UpstreamRouter) forwardToUpstream(ctx context.Context, upstreamID string, msg *mcp.Message) (*mcp.Message, error) {
	// Serialize access to this upstream's stdin pipe.
	muI, _ := r.ioMutexes.LoadOrStore(upstreamID, &sync.Mutex{})
	mu := muI.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	// Fetch a fresh connection inside the critical section so we never
	// use a stale lineCh from before a reconnect.
	writer, lineCh, err := r.manager.GetConnection(upstreamID)
	if err != nil {
		return nil, fmt.Errorf("upstream %s unavailable: %w", upstreamID, err)
	}

	// Write the raw message to upstream stdin (newline-delimited).
	data := msg.Raw
	if len(data) == 0 {
		return nil, fmt.Errorf("empty message to forward")
	}

	// Append newline if not already present.
	if data[len(data)-1] != '\n' {
		dataCopy := make([]byte, len(data), len(data)+1)
		copy(dataCopy, data)
		dataCopy = append(dataCopy, '\n')
		data = dataCopy
	}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("writing to upstream: %w", err)
	}

	// Read from the channel with timeout. Server-to-client notifications
	// (messages without "id" that have a "method" field) are forwarded to
	// the client via NotificationForwarder (H-4). The 30s timer is reset
	// on each notification received, so upstreams sending progress notifications
	// for extended periods won't trigger a spurious timeout.
	notifFwd := r.getNotificationForwarder()
	var responseBytes []byte
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-lineCh:
			if !ok {
				return nil, fmt.Errorf("upstream closed connection")
			}
			// Detect notifications (messages without "id" and with "method")
			var peek struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if json.Unmarshal(line, &peek) == nil && peek.ID == nil && peek.Method != "" {
				// Forward notification to client if a forwarder is set (H-4).
				if notifFwd != nil {
					notifFwd.ForwardNotification(line)
					r.logger.Debug("forwarded upstream notification", "method", peek.Method, "upstream", upstreamID)
				} else {
					r.logger.Debug("dropping upstream notification (no forwarder)", "method", peek.Method, "upstream", upstreamID)
				}
				// Reset timer: upstream is actively communicating via notifications.
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(30 * time.Second)
				continue
			}
			responseBytes = line
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, fmt.Errorf("timeout waiting for upstream response (30s)")
		}
		break
	}

	// Remap the response ID to match the client's request ID.
	clientID := msg.RawID()
	if clientID != nil {
		responseBytes = remapResponseID(responseBytes, clientID)
	}

	return &mcp.Message{
		Raw:       responseBytes,
		Direction: mcp.ServerToClient,
		Timestamp: time.Now(),
	}, nil
}

// remapResponseID replaces the "id" field in a JSON-RPC response with the given client ID.
// This ensures the response ID matches the original client request ID, even if the
// upstream assigned a different internal ID.
//
// The implementation operates on raw bytes to preserve the original JSON field order,
// which avoids confusing log analyzers that expect deterministic field ordering.
func remapResponseID(responseBytes []byte, clientID json.RawMessage) []byte {
	// Find the "id" key in the top-level JSON object and replace its value in-place.
	// We search for `"id":` and then skip the old value to splice in the new one.
	// This avoids unmarshaling into map[string]json.RawMessage which randomizes field order.
	idx := findTopLevelKey(responseBytes, "id")
	if idx < 0 {
		// "id" key not present — inject it after the opening '{'.
		// Find the first '{' in the response.
		braceIdx := -1
		for i, b := range responseBytes {
			if b == '{' {
				braceIdx = i
				break
			}
		}
		if braceIdx < 0 {
			return responseBytes
		}
		result := make([]byte, 0, len(responseBytes)+len(clientID)+6)
		result = append(result, responseBytes[:braceIdx+1]...)
		result = append(result, '"', 'i', 'd', '"', ':')
		result = append(result, clientID...)
		result = append(result, ',')
		result = append(result, responseBytes[braceIdx+1:]...)
		return result
	}

	// idx points to the start of the value after `"id":`.
	// Determine the end of the old value.
	valueEnd := skipJSONValue(responseBytes, idx)
	if valueEnd < 0 {
		return responseBytes
	}

	// Build the new response: prefix + new ID + suffix.
	result := make([]byte, 0, len(responseBytes))
	result = append(result, responseBytes[:idx]...)
	result = append(result, clientID...)
	result = append(result, responseBytes[valueEnd:]...)
	return result
}

// findTopLevelKey searches for a top-level JSON key and returns the byte offset
// of the value that follows it (after the colon and optional whitespace).
// Returns -1 if not found.
func findTopLevelKey(data []byte, key string) int {
	target := `"` + key + `"`
	depth := 0
	i := 0
	for i < len(data) {
		switch data[i] {
		case '{', '[':
			depth++
			i++
		case '}', ']':
			depth--
			i++
		case '"':
			// Read the full quoted string.
			strEnd := i + 1
			for strEnd < len(data) {
				if data[strEnd] == '\\' {
					strEnd += 2
					continue
				}
				if data[strEnd] == '"' {
					strEnd++
					break
				}
				strEnd++
			}
			// Check if this is our target key at depth 1 (top-level object).
			if depth == 1 && strEnd-i == len(target) && string(data[i:strEnd]) == target {
				// Skip optional whitespace and colon after the key.
				j := strEnd
				for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
					j++
				}
				if j < len(data) && data[j] == ':' {
					j++
					for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
						j++
					}
					return j
				}
			}
			i = strEnd
		default:
			i++
		}
	}
	return -1
}

// skipJSONValue skips over a single JSON value starting at data[start] and
// returns the index just past the value. Returns -1 on malformed input.
func skipJSONValue(data []byte, start int) int {
	if start >= len(data) {
		return -1
	}
	switch data[start] {
	case '"':
		// String: skip to closing unescaped quote.
		i := start + 1
		for i < len(data) {
			if data[i] == '\\' {
				i += 2
				continue
			}
			if data[i] == '"' {
				return i + 1
			}
			i++
		}
		return -1
	case '{', '[':
		// Object or array: match braces/brackets.
		depth := 0
		i := start
		for i < len(data) {
			switch data[i] {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1
				}
			case '"':
				// Skip string contents (may contain braces).
				i++
				for i < len(data) {
					if data[i] == '\\' {
						i += 2
						continue
					}
					if data[i] == '"' {
						break
					}
					i++
				}
			}
			i++
		}
		return -1
	default:
		// Number, bool, null: skip until delimiter.
		i := start
		for i < len(data) {
			if data[i] == ',' || data[i] == '}' || data[i] == ']' ||
				data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r' {
				return i
			}
			i++
		}
		return i
	}
}

// extractToolName extracts the tool name from a tools/call request's params.
func (r *UpstreamRouter) extractToolName(msg *mcp.Message) string {
	params := msg.ParseParams()
	if params == nil {
		return ""
	}
	name, ok := params["name"].(string)
	if !ok {
		return ""
	}
	return name
}

// buildErrorResponse constructs a JSON-RPC error response message.
func (r *UpstreamRouter) buildErrorResponse(msg *mcp.Message, code int64, message string) *mcp.Message {
	// Extract the request ID to include in the error response.
	rawID := msg.RawID()

	resp := jsonRPCError{
		JSONRPC: "2.0",
		Error: jsonRPCErrorDetail{
			Code:    code,
			Message: message,
		},
	}

	if rawID != nil {
		resp.ID = rawID
	} else {
		resp.ID = json.RawMessage("null")
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		r.logger.Error("failed to marshal error response", "error", err)
		return &mcp.Message{
			Raw:       []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal error"}}`),
			Direction: mcp.ServerToClient,
			Timestamp: time.Now(),
		}
	}

	return &mcp.Message{
		Raw:       raw,
		Direction: mcp.ServerToClient,
		Timestamp: time.Now(),
	}
}

// buildResultResponse constructs a JSON-RPC success response message.
func (r *UpstreamRouter) buildResultResponse(msg *mcp.Message, result interface{}) (*mcp.Message, error) {
	rawID := msg.RawID()

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshaling result: %w", err)
	}

	resp := jsonRPCResult{
		JSONRPC: "2.0",
		Result:  json.RawMessage(resultJSON),
	}

	if rawID != nil {
		resp.ID = rawID
	} else {
		resp.ID = json.RawMessage("null")
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshaling response: %w", err)
	}

	return &mcp.Message{
		Raw:       raw,
		Direction: mcp.ServerToClient,
		Timestamp: time.Now(),
	}, nil
}

// --- JSON response types ---

type jsonRPCError struct {
	JSONRPC string             `json:"jsonrpc"`
	ID      json.RawMessage    `json:"id"`
	Error   jsonRPCErrorDetail `json:"error"`
}

type jsonRPCErrorDetail struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

type jsonRPCResult struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
}

type toolEntry struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"` // L-12: MCP spec requires inputSchema even when empty
}

type toolsListResult struct {
	Tools      []toolEntry `json:"tools"`
	NextCursor *string     `json:"nextCursor,omitempty"`
}

// sanitizeToolName limits length and removes control characters from a tool name
// before including it in JSON-RPC error messages (L-9). This provides defense-in-depth
// independent of the ValidationInterceptor, preventing oversized or malicious tool
// names from appearing in error responses.
func sanitizeToolName(name string) string {
	const maxLen = 256
	if len(name) > maxLen {
		name = name[:maxLen]
	}
	// Allow only printable ASCII and common Unicode letters/digits;
	// strip control characters (< 0x20), DEL (0x7f), and C0/C1 range.
	cleaned := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b >= 0x20 && b != 0x7f {
			cleaned = append(cleaned, b)
		}
	}
	return string(cleaned)
}

// rawIDFromBytes extracts the "id" field from raw JSON bytes without caching (M-22).
// Returns nil if no "id" field is present (i.e. the message is a notification).
// This avoids the sync.Once caching in Message.RawID() which could return a stale
// value if msg.Raw were mutated after the first call.
func rawIDFromBytes(raw []byte) json.RawMessage {
	if raw == nil {
		return nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil
	}
	return envelope["id"]
}

// sanitizeClientFramework limits length and removes control characters from
// the client framework name received during MCP initialize (M-3).
func sanitizeClientFramework(name string) string {
	const maxLen = 128
	if len(name) > maxLen {
		name = name[:maxLen]
	}
	// Remove control characters (< 0x20) and DEL (0x7f).
	cleaned := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b >= 0x20 && b != 0x7f {
			cleaned = append(cleaned, b)
		}
	}
	return string(cleaned)
}

// rewriteToolNameInMessage replaces the "name" field inside the "params" of a
// JSON-RPC tools/call message. Used to strip the namespace prefix before forwarding
// to the upstream, which expects the bare tool name.
//
// The implementation operates on raw bytes (reusing findTopLevelKey/skipJSONValue)
// to preserve JSON field order, consistent with remapResponseID. Map-based
// marshaling would randomize field order, confusing log analyzers.
func rewriteToolNameInMessage(raw []byte, newName string) ([]byte, error) {
	// Step 1: Find "params" value in the top-level envelope.
	paramsValueStart := findTopLevelKey(raw, "params")
	if paramsValueStart < 0 || paramsValueStart >= len(raw) || raw[paramsValueStart] != '{' {
		return raw, nil
	}

	// Step 2: Find the end of the params object to get its byte range.
	paramsValueEnd := skipJSONValue(raw, paramsValueStart)
	if paramsValueEnd < 0 {
		return raw, nil
	}
	paramsBytes := raw[paramsValueStart:paramsValueEnd]

	// Step 3: Within the params object, find the "name" key's value.
	// findTopLevelKey works on any JSON object slice — it finds keys at depth=1.
	nameValueOffset := findTopLevelKey(paramsBytes, "name")
	if nameValueOffset < 0 {
		return raw, nil
	}

	// Convert offset within paramsBytes to absolute offset in raw.
	absNameValueStart := paramsValueStart + nameValueOffset

	// Step 4: Skip the old name value to find its end.
	oldValueEnd := skipJSONValue(raw, absNameValueStart)
	if oldValueEnd < 0 {
		return raw, nil
	}

	// Step 5: Build the new JSON string for the replacement name.
	newNameJSON, err := json.Marshal(newName)
	if err != nil {
		return nil, fmt.Errorf("marshal new name: %w", err)
	}

	// Step 6: Splice — prefix + new value + suffix.
	result := make([]byte, 0, len(raw)-(oldValueEnd-absNameValueStart)+len(newNameJSON))
	result = append(result, raw[:absNameValueStart]...)
	result = append(result, newNameJSON...)
	result = append(result, raw[oldValueEnd:]...)
	return result, nil
}

// Compile-time check that UpstreamRouter implements MessageInterceptor.
var _ MessageInterceptor = (*UpstreamRouter)(nil)
