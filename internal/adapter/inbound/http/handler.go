// Package http provides the HTTP transport adapter for the proxy.
package http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// MCPProtocolVersion is the MCP protocol version this handler supports.
const MCPProtocolVersion = "2025-11-25"

// maxRequestBodySize is the maximum allowed request body size (1 MB).
const maxRequestBodySize = 1 << 20

// MCPSessionIDHeader is the header for session identification.
const MCPSessionIDHeader = "Mcp-Session-Id"

// MCPProtocolVersionHeader is the header for protocol version.
const MCPProtocolVersionHeader = "MCP-Protocol-Version"

var validSessionIDRegexp = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)

// defaultOwnerTTL is the maximum time an owner entry can exist without any
// active SSE channel before it is reaped. Prevents unbounded growth of the
// owners map when clients never send DELETE (M-20).
const defaultOwnerTTL = 30 * time.Minute

// ownerEntry holds ownership info plus a creation timestamp for TTL cleanup.
type ownerEntry struct {
	hash      string
	createdAt time.Time
}

// sessionRegistry manages active SSE sessions for server-initiated messages.
type sessionRegistry struct {
	// sessions maps session ID to a slice of channels for SSE connections.
	// Multiple SSE connections can share the same session.
	mu         sync.RWMutex
	sessions   map[string][]chan []byte
	owners     map[string]*ownerEntry   // sessionID → owner info with TTL
	sseCounters map[string]*atomic.Uint64 // M-21: per-session monotonic SSE event ID counter
	stopClean  chan struct{}             // signals cleanup goroutine to stop
	cleanDone  chan struct{}             // closed when cleanup goroutine exits (L-19)
	stopOnce   sync.Once                 // prevents double-close panic on concurrent StopCleanup() calls
	onTerminate func(sessionID string)   // optional callback when a session is terminated
}

// newSessionRegistry creates a new session registry.
// NOTE: call startCleanup() after all fields (including onTerminate) are set
// to avoid a data race between the cleanup goroutine and option application.
func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		sessions:    make(map[string][]chan []byte),
		owners:      make(map[string]*ownerEntry),
		sseCounters: make(map[string]*atomic.Uint64),
		stopClean:   make(chan struct{}),
		cleanDone:   make(chan struct{}),
	}
}

// startCleanup launches the background cleanup goroutine.
// Must be called after all configuration (including onTerminate) is finalized.
func (r *sessionRegistry) startCleanup() {
	go r.cleanupLoop()
}

// StopCleanup terminates the background cleanup goroutine and waits for it
// to finish (with a 5-second timeout). Safe to call concurrently and multiple
// times (uses sync.Once internally to prevent double-close panic).
func (r *sessionRegistry) StopCleanup() {
	r.stopOnce.Do(func() {
		close(r.stopClean)
	})
	// L-19: Wait for cleanup goroutine to exit, with a reasonable timeout.
	select {
	case <-r.cleanDone:
	case <-time.After(5 * time.Second):
		slog.Warn("cleanup goroutine did not exit within timeout")
	}
}

// cleanupLoop periodically removes orphaned owner entries that have no active
// SSE channels and have exceeded defaultOwnerTTL (M-20).
func (r *sessionRegistry) cleanupLoop() {
	defer close(r.cleanDone) // L-19: signal that goroutine has exited
	ticker := time.NewTicker(defaultOwnerTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopClean:
			return
		case <-ticker.C:
			r.cleanupStaleOwners()
		}
	}
}

// cleanupStaleOwners removes owner entries older than defaultOwnerTTL that have
// no active SSE channels.
func (r *sessionRegistry) cleanupStaleOwners() {
	cutoff := time.Now().Add(-defaultOwnerTTL)
	var reaped []string
	r.mu.Lock()
	for id, entry := range r.owners {
		if entry.createdAt.Before(cutoff) {
			// Only reap if there are no active SSE channels for this session.
			if len(r.sessions[id]) == 0 {
				delete(r.owners, id)
				delete(r.sseCounters, id) // M-21: clean up per-session SSE counter
				reaped = append(reaped, id)
			}
		}
	}
	cb := r.onTerminate
	r.mu.Unlock()
	// Notify cleanup callback outside the lock (same pattern as terminate).
	if cb != nil {
		for _, id := range reaped {
			cb(id)
		}
	}
}

// register adds an SSE channel to a session.
func (r *sessionRegistry) register(sessionID string, ch chan []byte, ownerHash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[sessionID] = append(r.sessions[sessionID], ch)
	if entry, exists := r.owners[sessionID]; exists {
		// L-FE-10: Refresh TTL on reconnection so cleanupStaleOwners
		// doesn't reap sessions that are still actively reconnecting.
		entry.createdAt = time.Now()
	} else {
		r.owners[sessionID] = &ownerEntry{hash: ownerHash, createdAt: time.Now()}
	}
}

// unregister removes an SSE channel from a session.
func (r *sessionRegistry) unregister(sessionID string, ch chan []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	channels := r.sessions[sessionID]
	for i, c := range channels {
		if c == ch {
			// Remove channel from slice
			r.sessions[sessionID] = append(channels[:i], channels[i+1:]...)
			break
		}
	}
	// Remove empty session entries
	if len(r.sessions[sessionID]) == 0 {
		delete(r.sessions, sessionID)
		// NOTE: do NOT delete owners here — owner survives SSE reconnects
	}
}

// terminate closes all SSE channels for a session and removes ownership.
func (r *sessionRegistry) terminate(sessionID string) bool {
	r.mu.Lock()
	_, ownerExists := r.owners[sessionID]
	channels, chanExists := r.sessions[sessionID]
	if !ownerExists && !chanExists {
		r.mu.Unlock()
		return false
	}
	for _, ch := range channels {
		close(ch)
	}
	delete(r.sessions, sessionID)
	delete(r.owners, sessionID)
	delete(r.sseCounters, sessionID) // M-21: clean up per-session SSE counter
	cb := r.onTerminate
	r.mu.Unlock()
	// Call cleanup callback outside the lock to avoid potential deadlocks.
	if cb != nil {
		cb(sessionID)
	}
	return true
}

// closeAll closes all SSE channels for all sessions and stops the cleanup goroutine.
func (r *sessionRegistry) closeAll() {
	r.StopCleanup()
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, channels := range r.sessions {
		for _, ch := range channels {
			close(ch)
		}
	}
	r.sessions = make(map[string][]chan []byte)
	r.owners = make(map[string]*ownerEntry)
	r.sseCounters = make(map[string]*atomic.Uint64) // M-21: reset per-session SSE counters
}

// broadcast sends a message to ONE SSE channel per session.
// MCP spec: "MUST send each JSON-RPC message on only one of the
// connected streams" — pick the first available channel per session.
func (r *sessionRegistry) broadcast(data []byte) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for sid, channels := range r.sessions {
		if len(channels) == 0 {
			continue
		}
		sent := false
		for _, ch := range channels {
			select {
			case ch <- data:
				sent = true
			default:
				continue
			}
			if sent {
				break
			}
		}
		if !sent {
			slog.Debug("broadcast: notification dropped, all channels full", "session_id", sid)
		}
	}
}

// nextSSEEventID returns the next monotonically increasing SSE event ID for
// a session. Creates the counter if it doesn't exist yet (M-21).
func (r *sessionRegistry) nextSSEEventID(sessionID string) uint64 {
	r.mu.Lock()
	counter, exists := r.sseCounters[sessionID]
	if !exists {
		counter = &atomic.Uint64{}
		r.sseCounters[sessionID] = counter
	}
	r.mu.Unlock()
	return counter.Add(1)
}

// preRegisterOwner records ownership before the SSE channel is created.
func (r *sessionRegistry) preRegisterOwner(sessionID, ownerHash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.owners[sessionID]; !exists {
		r.owners[sessionID] = &ownerEntry{hash: ownerHash, createdAt: time.Now()}
	}
}

// verifyOwner checks if the caller owns the session.
func (r *sessionRegistry) verifyOwner(sessionID, ownerHash string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, exists := r.owners[sessionID]
	if !exists {
		return false // Unknown session → DENY
	}
	// M-14: Use constant-time comparison to prevent timing side-channel.
	// M-16: In unauthenticated mode both hashes are empty — ownership is
	// not enforced by design (localhost-only access assumed).
	if len(entry.hash) == 0 && len(ownerHash) == 0 {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(entry.hash), []byte(ownerHash)) == 1
}

// sessionExists returns true if the session ID is known to the registry
// (either has an owner entry or active SSE channels).
func (r *sessionRegistry) sessionExists(sessionID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ownerExists := r.owners[sessionID]
	_, chanExists := r.sessions[sessionID]
	return ownerExists || chanExists
}

// ownerHashFromRequest computes the SHA-256 hex digest of the API key in the request context.
func ownerHashFromRequest(r *http.Request) string {
	apiKey, _ := r.Context().Value(proxy.APIKeyContextKey).(string)
	if apiKey == "" {
		return ""
	}
	h := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(h[:]) // Full 32 bytes
}

// mcpHandler creates the main HTTP handler for MCP Streamable HTTP transport.
// It routes requests by HTTP method to the appropriate handler.
func mcpHandler(proxyService *service.ProxyService, registry *sessionRegistry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handlePost(w, r, proxyService, registry)
		case http.MethodGet:
			handleGet(w, r, registry)
		case http.MethodDelete:
			handleDelete(w, r, registry)
		case http.MethodOptions:
			handleOptions(w, r)
		default:
			w.Header().Set("Allow", "GET, POST, DELETE, OPTIONS")
			// L-26: Use writeJSONError for consistent JSON error responses.
			writeJSONError(w, http.StatusMethodNotAllowed, "Method Not Allowed")
		}
	})
}

// handlePost processes JSON-RPC messages from the client.
// It reads the request body, passes it through the proxy service,
// and returns the response.
func handlePost(w http.ResponseWriter, r *http.Request, proxyService *service.ProxyService, registry *sessionRegistry) {
	setCORSHeaders(w, r)

	// MCP quality: log warning if Accept header is present but doesn't include
	// application/json or text/event-stream (expected by MCP Streamable HTTP).
	// Not blocking for backward compatibility.
	if accept := r.Header.Get("Accept"); accept != "" {
		if !strings.Contains(accept, "application/json") &&
			!strings.Contains(accept, "text/event-stream") &&
			!strings.Contains(accept, "*/*") {
			slog.Warn("POST Accept header doesn't include application/json or text/event-stream",
				"accept", accept)
		}
	}

	// MCP spec: validate MCP-Protocol-Version header. If present and
	// unsupported, MUST respond with HTTP 400 Bad Request.
	if protoVer := r.Header.Get(MCPProtocolVersionHeader); protoVer != "" {
		if protoVer != MCPProtocolVersion {
			writeJSONError(w, http.StatusBadRequest,
				"Unsupported MCP protocol version: "+protoVer+
					" (supported: "+MCPProtocolVersion+")")
			return
		}
	}

	// Validate content type (before reading body to fail fast)
	// M-38: MCP Streamable HTTP requires Content-Type: application/json
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		// M-17: Use writeJSONRPCError (HTTP 200 + JSON-RPC error) for consistency
		writeJSONRPCError(w, nil, -32700, "Parse error: Content-Type header required (must be application/json)")
		return
	}
	mediaType, _, _ := mime.ParseMediaType(contentType)
	if mediaType != "application/json" {
		// M-17: Use writeJSONRPCError (HTTP 200 + JSON-RPC error) for consistency
		writeJSONRPCError(w, nil, -32700, "Parse error: content type must be application/json")
		return
	}

	// Apply payload size limit before reading body
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	defer func() { _ = r.Body.Close() }()

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// Check if the error is due to exceeding the size limit
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSONRPCError(w, nil, -32700, "Parse error: request body too large (max 1MB)")
			return
		}
		writeJSONRPCError(w, nil, -32700, "Parse error: failed to read request body")
		return
	}

	// Check for empty body
	if len(body) == 0 {
		writeJSONRPCError(w, nil, -32700, "Parse error: empty request body")
		return
	}

	// Validate JSON syntax
	if !json.Valid(body) {
		writeJSONRPCError(w, nil, -32700, "Parse error: invalid JSON")
		return
	}

	// Validate JSON-RPC required fields
	var rpcRequest struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
	}
	if err := json.Unmarshal(body, &rpcRequest); err != nil {
		// JSON is valid (passed json.Valid above) but not an object -
		// e.g., array, string, number, boolean
		writeJSONRPCError(w, nil, -32600, "Invalid Request: request must be a JSON object")
		return
	}
	if rpcRequest.JSONRPC != "2.0" {
		writeJSONRPCError(w, nil, -32600, "Invalid Request: missing or invalid jsonrpc version (must be \"2.0\")")
		return
	}
	if rpcRequest.Method == "" {
		writeJSONRPCError(w, nil, -32600, "Invalid Request: missing method field")
		return
	}

	// Determine if this is a notification (no "id" field) per JSON-RPC 2.0.
	// Notifications don't expect a response; Streamable HTTP requires 202 Accepted.
	var idCheck struct {
		ID json.RawMessage `json:"id"`
	}
	_ = json.Unmarshal(body, &idCheck)
	isNotification := idCheck.ID == nil

	// Validate id type: per JSON-RPC 2.0, id MUST be string, number, or null.
	// M-20: Also reject arrays ([) and objects ({) which are not valid id types.
	if idCheck.ID != nil {
		trimmed := bytes.TrimSpace(idCheck.ID)
		if len(trimmed) > 0 {
			first := trimmed[0]
			if first != '"' && first != 'n' && (first < '0' || first > '9') && first != '-' {
				writeJSONRPCError(w, idCheck.ID, -32600, "Invalid Request: id must be a string, number, or null")
				return
			}
			if first == '[' || first == '{' {
				writeJSONRPCError(w, idCheck.ID, -32600, "Invalid Request: id must be a string, number, or null")
				return
			}
		}
	}

	// M-18: Validate session ID BEFORE proxy execution to reject invalid
	// sessions early and avoid wasted work.
	if sessionID := r.Header.Get(MCPSessionIDHeader); sessionID != "" {
		if len(sessionID) > 128 || !validSessionIDRegexp.MatchString(sessionID) {
			writeJSONRPCError(w, idCheck.ID, -32600, "Invalid Request: invalid session ID")
			return
		}
	}

	// MCP spec: "If a server receives an HTTP request with an unknown
	// Mcp-Session-Id, it MUST respond with HTTP 404 Not Found."
	if sessionID := r.Header.Get(MCPSessionIDHeader); sessionID != "" {
		if registry != nil && !registry.sessionExists(sessionID) {
			writeJSONError(w, http.StatusNotFound, "Session not found")
			return
		}
	}

	// Create pipe for bidirectional communication with proxy service
	// The proxy service expects io.Reader (input) and io.Writer (output)
	// L-29: Use three-index slice to force new allocation and prevent in-place mutation of body.
	clientReader := bytes.NewReader(append(body[:len(body):len(body)], '\n')) // Add newline for line-delimited JSON
	responseBuffer := &bytes.Buffer{}

	// NOTE: Notifications pass through the full proxy/interceptor pipeline before
	// returning 202. Ideally they would be short-circuited here, but the proxy
	// service needs to see them for session tracking and audit. The UpstreamRouter
	// already drops notifications (no "id") to prevent DoS, so the pipeline cost
	// is bounded to the interceptor chain only.

	// Run through proxy service
	// Use request context so cancellation propagates.
	// Inject a session-ID write-back slot so AuthInterceptor can share the
	// domain session ID with us (for the Mcp-Session-Id response header).
	var domainSessionID string
	ctx := context.WithValue(r.Context(), proxy.SessionIDSlotKey, &domainSessionID)
	if err := proxyService.Run(ctx, clientReader, responseBuffer); err != nil {
		// Check if it's a context cancellation (client disconnected)
		if ctx.Err() != nil {
			return // Client disconnected, don't write response
		}
		// Proxy service error - log and return internal error
		slog.Error("proxy service error", "error", err)
		writeJSONRPCError(w, nil, -32603, "Internal error")
		return
	}

	// Common response headers
	w.Header().Set(MCPProtocolVersionHeader, MCPProtocolVersion)

	// M-4: Echo session ID only after verifying ownership.
	if sessionID := r.Header.Get(MCPSessionIDHeader); sessionID != "" {
		ownerHash := ownerHashFromRequest(r)
		if registry.verifyOwner(sessionID, ownerHash) {
			w.Header().Set(MCPSessionIDHeader, sessionID)
		}
	}

	// For notifications (no id), return 202 Accepted with no body per Streamable HTTP spec.
	if isNotification {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Write JSON-RPC response (trim trailing newline added by proxy)
	w.Header().Set("Content-Type", "application/json")
	response := bytes.TrimSuffix(responseBuffer.Bytes(), []byte("\n"))

	// Defensive: if the buffer contains multiple JSON-RPC messages
	// (e.g. progress notifications + final result), extract only the
	// response that matches the request ID.
	if len(idCheck.ID) > 0 {
		response = filterResponseByID(response, idCheck.ID)
	}

	// MCP spec compliance: promote auth errors to HTTP 401.
	// The interceptor chain writes auth failures as JSON-RPC errors in the
	// response buffer (HTTP-agnostic). We detect them here and return the
	// proper HTTP status code with WWW-Authenticate header per RFC 9728.
	if isAuthErrorResponse(response) {
		w.Header().Set("WWW-Authenticate",
			`Bearer resource_metadata="/.well-known/oauth-protected-resource"`)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(MCPProtocolVersionHeader, MCPProtocolVersion)
		w.Header().Set("Content-Length", strconv.Itoa(len(response)))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(response)
		return
	}

	// For initialize requests, generate and return a session ID only when
	// the response is a success (has "result", no "error"). This prevents
	// leaking a valid session ID alongside a JSON-RPC error body (H-6).
	if rpcRequest.Method == "initialize" {
		var respCheck struct {
			Error json.RawMessage `json:"error"`
		}
		isError := json.Unmarshal(response, &respCheck) == nil && len(respCheck.Error) > 0
		if !isError {
			// Use the domain session ID from AuthInterceptor (shared via context slot)
			// so the client-visible Mcp-Session-Id matches audit record session_id.
			sid := domainSessionID
			if sid == "" {
				// Fallback: generate a new ID if the interceptor didn't populate the slot
				// (e.g., unauthenticated requests or anonymous sessions).
				sid, _ = session.GenerateSessionID()
			}
			if sid != "" {
				w.Header().Set(MCPSessionIDHeader, sid)
				ownerHash := ownerHashFromRequest(r)
				registry.preRegisterOwner(sid, ownerHash)
			}
		}
	}

	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		// M-21: Use per-session monotonic counter for SSE event ID instead of hardcoded "id: 1".
		// M-3: For initialize, session ID is in response header, not request header.
		sessionID := r.Header.Get(MCPSessionIDHeader)
		if sessionID == "" {
			sessionID = w.Header().Get(MCPSessionIDHeader)
		}
		// M-2: Skip SSE counter for empty session IDs to avoid leaking a shared counter.
		var eventID uint64 = 1
		if sessionID != "" {
			eventID = registry.nextSSEEventID(sessionID)
		}
		// L-11: Use w.Write instead of fmt.Fprintf to avoid %-verb interpretation in SSE data.
		normalized := sseNormalize(response)
		sseFrame := fmt.Appendf(nil, "id: %d\nevent: message\ndata: ", eventID)
		sseFrame = append(sseFrame, normalized...)
		sseFrame = append(sseFrame, '\n', '\n')
		_, _ = w.Write(sseFrame)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		return
	}

	w.Header().Set("Content-Length", strconv.Itoa(len(response)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// filterResponseByID extracts the JSON-RPC response matching expectedID from buffer.
// If the buffer is a single JSON object with the right ID, it is returned as-is.
// Otherwise, it uses json.Decoder to split multiple concatenated JSON objects
// (NOT newline-based splitting, which corrupts JSON strings containing literal newlines).
func filterResponseByID(buffer []byte, expectedID json.RawMessage) []byte {
	// Fast path: buffer is a single JSON object with matching ID.
	var single struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(buffer, &single) == nil && bytes.Equal(single.ID, expectedID) {
		return buffer
	}

	// If the buffer looks like a SINGLE JSON object (no "}\n{" boundary between
	// separate objects), return it as-is. Upstream MCP servers may embed literal
	// newline bytes (0x0A) in JSON string values, which is technically invalid JSON
	// but common in practice. Splitting by newlines would corrupt such responses.
	trimmed := bytes.TrimSpace(buffer)
	if len(trimmed) > 0 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}' &&
		!bytes.Contains(trimmed, []byte("}\n{")) {
		return trimmed
	}

	// Slow path: use json.Decoder for multiple concatenated JSON objects.
	dec := json.NewDecoder(bytes.NewReader(buffer))
	var firstObject json.RawMessage
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			break
		}
		if firstObject == nil {
			firstObject = raw
		}
		var candidate struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(raw, &candidate) == nil && bytes.Equal(candidate.ID, expectedID) {
			return raw
		}
	}

	if firstObject != nil {
		return firstObject
	}
	return buffer
}

// sseNormalize sanitizes SSE data to prevent newline injection.
// Order: CRLF → LF, bare CR → LF, then fold multi-line into separate data: fields.
func sseNormalize(msg []byte) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, msg); err == nil {
		return buf.Bytes()
	}
	s := string(msg)
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return []byte(s)
}

// handleGet opens an SSE stream for server-initiated messages.
// This is used for long-running connections where the server needs to
// push messages to the client (e.g., progress notifications).
func handleGet(w http.ResponseWriter, r *http.Request, registry *sessionRegistry) {
	setCORSHeaders(w, r)

	// MCP spec: validate MCP-Protocol-Version header.
	if protoVer := r.Header.Get(MCPProtocolVersionHeader); protoVer != "" {
		if protoVer != MCPProtocolVersion {
			writeJSONError(w, http.StatusBadRequest,
				"Unsupported MCP protocol version: "+protoVer+
					" (supported: "+MCPProtocolVersion+")")
			return
		}
	}

	// M-21: Log warning if client sends Last-Event-ID (SSE reconnection).
	// Event replay is not supported; the client will receive new events only.
	// L-8: Truncate Last-Event-ID before logging to prevent log pollution (max 128 chars).
	if lastID := r.Header.Get("Last-Event-ID"); lastID != "" {
		logID := lastID
		if len(logID) > 128 {
			logID = logID[:128] + "...(truncated)"
		}
		slog.Warn("SSE reconnection detected but replay not supported", "last_event_id", logID)
	}

	// L-16: Validate Accept header. Allow text/event-stream, empty (curl-style),
	// and wildcard (*/*). Reject explicit non-SSE accept types with 406.
	accept := r.Header.Get("Accept")
	if accept != "" && !strings.Contains(accept, "text/event-stream") && !strings.Contains(accept, "*/*") {
		// L-26: Use writeJSONError for consistent JSON error responses.
		writeJSONError(w, http.StatusNotAcceptable, "Not Acceptable: SSE endpoint requires Accept: text/event-stream")
		return
	}

	// SSE requires Flusher support
	flusher, ok := w.(http.Flusher)
	if !ok {
		// L-26: Use writeJSONError for consistent JSON error responses.
		writeJSONError(w, http.StatusInternalServerError, "SSE not supported")
		return
	}

	// Extract session ID (required for SSE)
	sessionID := r.Header.Get(MCPSessionIDHeader)
	if sessionID == "" {
		// L-26: Use writeJSONError for consistent JSON error responses.
		writeJSONError(w, http.StatusBadRequest, "Mcp-Session-Id header required for SSE")
		return
	}
	if len(sessionID) > 128 || !validSessionIDRegexp.MatchString(sessionID) {
		// L-26: Use writeJSONError for consistent JSON error responses.
		writeJSONError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	// MCP spec: unknown session → 404
	if !registry.sessionExists(sessionID) {
		writeJSONError(w, http.StatusNotFound, "Session not found")
		return
	}
	// Verify session ownership before setting any session-related headers
	// to avoid leaking the session ID in error responses.
	ownerHash := ownerHashFromRequest(r)
	if !registry.verifyOwner(sessionID, ownerHash) {
		// L-26: Use writeJSONError for consistent JSON error responses.
		writeJSONError(w, http.StatusForbidden, "Forbidden: session not owned by caller")
		return
	}

	// Set SSE headers (after ownership verification succeeds)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set(MCPProtocolVersionHeader, MCPProtocolVersion)
	w.Header().Set(MCPSessionIDHeader, sessionID)

	// Create channel for messages
	msgChan := make(chan []byte, 100) // Buffer for some messages
	registry.register(sessionID, msgChan, ownerHash)
	defer registry.unregister(sessionID, msgChan)

	// Get request context for cancellation
	ctx := r.Context()

	// Write initial comment to establish connection
	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	// M-19: Add 30s heartbeat/keepalive to prevent reverse proxies from
	// closing idle SSE connections, matching admin SSE endpoints.
	keepalive := time.NewTimer(30 * time.Second)
	defer keepalive.Stop()

	// Event loop
	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			return
		case <-keepalive.C:
			// M-47: Check write errors — client disconnect means stop.
			if _, writeErr := fmt.Fprintf(w, ": keepalive\n\n"); writeErr != nil {
				return
			}
			flusher.Flush()
			keepalive.Reset(30 * time.Second)
		case msg, ok := <-msgChan:
			if !ok {
				// Channel closed (session terminated)
				return
			}
			// M-21/M-36/M-37: Use per-session monotonic SSE event ID counter
			// shared between GET and POST paths.
			id := registry.nextSSEEventID(sessionID)
			// L-11: Use w.Write instead of fmt.Fprintf to avoid %-verb interpretation in SSE data.
			normalized := sseNormalize(msg)
			sseFrame := fmt.Appendf(nil, "id: %d\nevent: message\ndata: ", id)
			sseFrame = append(sseFrame, normalized...)
			sseFrame = append(sseFrame, '\n', '\n')
			// M-47: Check write errors.
			if _, writeErr := w.Write(sseFrame); writeErr != nil {
				return
			}
			flusher.Flush()
			// M-19: Reset keepalive timer since we just sent data.
			if !keepalive.Stop() {
				select {
				case <-keepalive.C:
				default:
				}
			}
			keepalive.Reset(30 * time.Second)
		}
	}
}

// handleDelete terminates a session and closes all associated SSE connections.
func handleDelete(w http.ResponseWriter, r *http.Request, registry *sessionRegistry) {
	setCORSHeaders(w, r)
	sessionID := r.Header.Get(MCPSessionIDHeader)
	if sessionID == "" {
		// M-27: Use JSON-RPC error instead of text/plain on MCP endpoint
		writeJSONRPCError(w, nil, -32600, "Mcp-Session-Id header required")
		return
	}
	if len(sessionID) > 128 || !validSessionIDRegexp.MatchString(sessionID) {
		// M-27: Use JSON-RPC error instead of text/plain on MCP endpoint
		writeJSONRPCError(w, nil, -32600, "invalid session ID")
		return
	}

	// MCP spec: unknown session → 404
	if !registry.sessionExists(sessionID) {
		writeJSONError(w, http.StatusNotFound, "Session not found")
		return
	}
	ownerHash := ownerHashFromRequest(r)
	if !registry.verifyOwner(sessionID, ownerHash) {
		writeJSONError(w, http.StatusForbidden, "Forbidden: session not owned by caller")
		return
	}

	if !registry.terminate(sessionID) {
		writeJSONError(w, http.StatusNotFound, "Session not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// setCORSHeaders sets CORS headers only for allowed local origins.
func setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	w.Header().Add("Vary", "Origin")

	u, err := url.Parse(origin)
	if err != nil {
		return
	}
	host := u.Hostname() // strips port and IPv6 brackets
	switch host {
	case "localhost", "127.0.0.1", "::1":
		// Local origin allowed
	default:
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, MCP-Protocol-Version")
}

// handleOptions handles CORS preflight requests.
func handleOptions(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)
	// Allow common headers
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Session-Id, MCP-Protocol-Version")
	w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours
	w.WriteHeader(http.StatusNoContent)
}

// jsonRPCError represents a JSON-RPC 2.0 error response.
type jsonRPCError struct {
	JSONRPC string            `json:"jsonrpc"`
	ID      interface{}       `json:"id"`
	Error   jsonRPCErrorField `json:"error"`
}

type jsonRPCErrorField struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// writeJSONRPCError writes a JSON-RPC error response.
func writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // JSON-RPC errors still return 200 OK

	// Explicitly serialize nil as JSON null via json.RawMessage to avoid
	// relying on the implicit Go nil-interface-to-null behavior.
	actualID := id
	if actualID == nil {
		actualID = json.RawMessage("null")
	}

	errResp := jsonRPCError{
		JSONRPC: "2.0",
		ID:      actualID,
		Error: jsonRPCErrorField{
			Code:    code,
			Message: message,
		},
	}

	data, err := json.Marshal(errResp)
	if err != nil {
		slog.Error("failed to encode JSON-RPC error response", "error", err)
		return
	}
	_, _ = w.Write(data)
}

// writeJSONError writes a JSON error response with the given status code and message.
// L-26: Provides consistent JSON error responses instead of text/plain from http.Error().
func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	resp := map[string]string{"error": message}
	data, err := json.Marshal(resp)
	if err != nil {
		slog.Error("failed to encode JSON error response", "error", err)
		return
	}
	_, _ = w.Write(data)
}

// isAuthErrorResponse inspects a JSON-RPC response buffer to detect
// authentication errors. Returns true if the response contains an auth
// error that should be promoted to HTTP 401.
// The checked strings are the exact outputs of proxy.SafeErrorMessage()
// for ErrUnauthenticated, ErrInvalidAPIKey, and ErrSessionExpired
// (defined in proxy/auth_interceptor.go:62-67).
func isAuthErrorResponse(response []byte) bool {
	var parsed struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response, &parsed); err != nil || parsed.Error == nil {
		return false
	}
	switch parsed.Error.Message {
	case "Authentication required", "Invalid API key", "Session expired":
		return true
	}
	return false
}

// healthHandler returns an HTTP handler that responds with 200 OK for health checks.
func healthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}
