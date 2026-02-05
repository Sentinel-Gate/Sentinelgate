// Package http provides the HTTP transport adapter for the proxy.
package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// MCPProtocolVersion is the MCP protocol version this handler supports.
const MCPProtocolVersion = "2025-06-18"

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
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONRPCError(w, nil, -32700, "Parse error: failed to read request body")
		return
	}
	defer r.Body.Close()

	// Validate content type
	contentType := r.Header.Get("Content-Type")
	if contentType != "" && contentType != "application/json" {
		writeJSONRPCError(w, nil, -32700, "Parse error: content type must be application/json")
		return
	}

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

	// Set response headers
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(MCPProtocolVersionHeader, MCPProtocolVersion)

	// Echo session ID if present
	if sessionID := r.Header.Get(MCPSessionIDHeader); sessionID != "" {
		w.Header().Set(MCPSessionIDHeader, sessionID)
	}

	// Write response (trim trailing newline added by proxy)
	response := bytes.TrimSuffix(responseBuffer.Bytes(), []byte("\n"))
	w.WriteHeader(http.StatusOK)
	w.Write(response)
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
	fmt.Fprintf(w, ": connected\n\n")
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
			fmt.Fprintf(w, "data: %s\n\n", msg)
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

	json.NewEncoder(w).Encode(errResp)
}

// healthHandler returns an HTTP handler that responds with 200 OK for health checks.
func healthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
}
