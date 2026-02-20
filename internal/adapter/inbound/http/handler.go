// Package http provides the HTTP transport adapter for the proxy.
package http

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// MCPProtocolVersion is the MCP protocol version this handler supports.
const MCPProtocolVersion = "2025-06-18"

// maxRequestBodySize is the maximum allowed request body size (1 MB).
const maxRequestBodySize = 1 << 20

// MCPSessionIDHeader is the header for session identification.
const MCPSessionIDHeader = "Mcp-Session-Id"

// MCPProtocolVersionHeader is the header for protocol version.
const MCPProtocolVersionHeader = "MCP-Protocol-Version"

// sessionRegistry manages active SSE sessions for server-initiated messages.
type sessionRegistry struct {
	// sessions maps session ID to a slice of channels for SSE connections.
	// Multiple SSE connections can share the same session.
	mu       sync.RWMutex
	sessions map[string][]chan []byte
}

// newSessionRegistry creates a new session registry.
func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{
		sessions: make(map[string][]chan []byte),
	}
}

// register adds an SSE channel to a session.
func (r *sessionRegistry) register(sessionID string, ch chan []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[sessionID] = append(r.sessions[sessionID], ch)
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
	}
}

// terminate closes all SSE channels for a session.
func (r *sessionRegistry) terminate(sessionID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	channels, exists := r.sessions[sessionID]
	if !exists {
		return false
	}
	for _, ch := range channels {
		close(ch)
	}
	delete(r.sessions, sessionID)
	return true
}

// closeAll closes all SSE channels for all sessions.
func (r *sessionRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, channels := range r.sessions {
		for _, ch := range channels {
			close(ch)
		}
	}
	r.sessions = make(map[string][]chan []byte)
}

// mcpHandler creates the main HTTP handler for MCP Streamable HTTP transport.
// It routes requests by HTTP method to the appropriate handler.
func mcpHandler(proxyService *service.ProxyService, registry *sessionRegistry) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handlePost(w, r, proxyService)
		case http.MethodGet:
			handleGet(w, r, registry)
		case http.MethodDelete:
			handleDelete(w, r, registry)
		case http.MethodOptions:
			handleOptions(w, r)
		default:
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})
}

// handlePost processes JSON-RPC messages from the client.
// It reads the request body, passes it through the proxy service,
// and returns the response.
func handlePost(w http.ResponseWriter, r *http.Request, proxyService *service.ProxyService) {
	// Validate content type (before reading body to fail fast)
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && contentType != "application/json" {
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

	// Create pipe for bidirectional communication with proxy service
	// The proxy service expects io.Reader (input) and io.Writer (output)
	clientReader := bytes.NewReader(append(body, '\n')) // Add newline for line-delimited JSON
	responseBuffer := &bytes.Buffer{}

	// Run through proxy service
	// Use request context so cancellation propagates
	ctx := r.Context()
	if err := proxyService.Run(ctx, clientReader, responseBuffer); err != nil {
		// Check if it's a context cancellation (client disconnected)
		if ctx.Err() != nil {
			return // Client disconnected, don't write response
		}
		// Proxy service error - log and return internal error
		writeJSONRPCError(w, nil, -32603, "Internal error")
		return
	}

	// Common response headers
	w.Header().Set(MCPProtocolVersionHeader, MCPProtocolVersion)

	// Echo session ID if client sent one
	if sessionID := r.Header.Get(MCPSessionIDHeader); sessionID != "" {
		w.Header().Set(MCPSessionIDHeader, sessionID)
	}

	// For notifications (no id), return 202 Accepted with no body per Streamable HTTP spec.
	if isNotification {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// For initialize requests, generate and return a session ID.
	// Clients (e.g. Codex/rmcp) require this to establish a session.
	if rpcRequest.Method == "initialize" {
		if sid, err := session.GenerateSessionID(); err == nil {
			w.Header().Set(MCPSessionIDHeader, sid)
		}
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

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

// filterResponseByID extracts the JSON-RPC response matching expectedID from buffer.
// If the buffer is a single JSON object with the right ID, it is returned as-is.
// Otherwise, the buffer is split by newlines and the first line with a matching ID
// is returned. As a last resort, the first non-empty line is returned.
func filterResponseByID(buffer []byte, expectedID json.RawMessage) []byte {
	// Fast path: buffer is a single JSON object with matching ID.
	var single struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(buffer, &single) == nil && bytes.Equal(single.ID, expectedID) {
		return buffer
	}

	// Slow path: multiple newline-delimited JSON objects.
	lines := bytes.Split(buffer, []byte("\n"))
	var firstNonEmpty []byte
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if firstNonEmpty == nil {
			firstNonEmpty = line
		}
		var candidate struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(line, &candidate) == nil && bytes.Equal(candidate.ID, expectedID) {
			return line
		}
	}

	// Fallback: return first non-empty line (or original buffer).
	if firstNonEmpty != nil {
		return firstNonEmpty
	}
	return buffer
}

// handleGet opens an SSE stream for server-initiated messages.
// This is used for long-running connections where the server needs to
// push messages to the client (e.g., progress notifications).
func handleGet(w http.ResponseWriter, r *http.Request, registry *sessionRegistry) {
	// SSE requires Flusher support
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Extract session ID (required for SSE)
	sessionID := r.Header.Get(MCPSessionIDHeader)
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required for SSE", http.StatusBadRequest)
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set(MCPProtocolVersionHeader, MCPProtocolVersion)
	w.Header().Set(MCPSessionIDHeader, sessionID)

	// Create channel for messages
	msgChan := make(chan []byte, 100) // Buffer for some messages
	registry.register(sessionID, msgChan)
	defer registry.unregister(sessionID, msgChan)

	// Get request context for cancellation
	ctx := r.Context()

	// Write initial comment to establish connection
	_, _ = fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	// Event loop
	for {
		select {
		case <-ctx.Done():
			// Client disconnected
			return
		case msg, ok := <-msgChan:
			if !ok {
				// Channel closed (session terminated)
				return
			}
			// Write SSE format: "data: <json>\n\n"
			_, _ = fmt.Fprintf(w, "data: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

// handleDelete terminates a session and closes all associated SSE connections.
func handleDelete(w http.ResponseWriter, r *http.Request, registry *sessionRegistry) {
	sessionID := r.Header.Get(MCPSessionIDHeader)
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}

	if !registry.terminate(sessionID) {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleOptions handles CORS preflight requests.
func handleOptions(w http.ResponseWriter, r *http.Request) {
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

	errResp := jsonRPCError{
		JSONRPC: "2.0",
		ID:      id,
		Error: jsonRPCErrorField{
			Code:    code,
			Message: message,
		},
	}

	_ = json.NewEncoder(w).Encode(errResp)
}

// healthHandler returns an HTTP handler that responds with 200 OK for health checks.
func healthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}
