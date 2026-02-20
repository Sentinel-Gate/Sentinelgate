// Package proxy contains the core domain logic for the MCP proxy.
package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// JSON-RPC error codes used by the router.
const (
	// ErrCodeMethodNotFound is returned when a tool is not found in any upstream.
	ErrCodeMethodNotFound int64 = -32601
	// ErrCodeInternal is returned when an upstream connection fails.
	ErrCodeInternal int64 = -32603
	// ErrCodeNoUpstreams is returned when no upstreams are available (503-equivalent).
	ErrCodeNoUpstreams int64 = -32000
)

// RoutableTool represents a tool that can be routed to a specific upstream.
// This is a minimal struct with just the fields the router needs, avoiding
// circular imports with the upstream package's DiscoveredTool type.
type RoutableTool struct {
	// Name is the tool's unique name.
	Name string
	// UpstreamID identifies which upstream owns this tool.
	UpstreamID string
	// Description is the human-readable tool description.
	Description string
	// InputSchema is the JSON Schema for the tool's input parameters.
	InputSchema json.RawMessage
}

// ToolCacheReader provides read access to the shared tool cache.
// The ToolCache from the upstream package will satisfy this interface.
type ToolCacheReader interface {
	// GetTool looks up a tool by name. Returns the tool and true if found.
	GetTool(name string) (*RoutableTool, bool)
	// GetAllTools returns all discovered tools across all upstreams.
	GetAllTools() []*RoutableTool
}

// UpstreamConnectionProvider provides access to upstream connections.
// The UpstreamManager will satisfy this interface.
type UpstreamConnectionProvider interface {
	// GetConnection returns the stdin writer and stdout reader for an upstream.
	GetConnection(upstreamID string) (io.WriteCloser, io.ReadCloser, error)
	// AllConnected returns true if at least one upstream is connected.
	AllConnected() bool
}

// UpstreamRouter routes MCP messages to the appropriate upstream based on
// tool name lookup in the shared ToolCache. It is the innermost interceptor
// in the chain for multi-upstream mode.
type UpstreamRouter struct {
	toolCache ToolCacheReader
	manager   UpstreamConnectionProvider
	logger    *slog.Logger
}

// NewUpstreamRouter creates a new UpstreamRouter.
func NewUpstreamRouter(cache ToolCacheReader, manager UpstreamConnectionProvider, logger *slog.Logger) *UpstreamRouter {
	return &UpstreamRouter{
		toolCache: cache,
		manager:   manager,
		logger:    logger,
	}
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

	// Check if any upstreams are available.
	if !r.manager.AllConnected() {
		r.logger.Warn("no upstreams available")
		return r.buildErrorResponse(msg, ErrCodeNoUpstreams, "No upstreams available"), nil
	}

	method := msg.Method()

	switch method {
	case "initialize":
		return r.handleInitialize(msg)
	case "notifications/initialized", "initialized":
		// Client acknowledgement — no response needed, just consume it.
		return r.buildResultResponse(msg, map[string]any{})
	case "tools/list":
		return r.handleToolsList(msg)
	case "tools/call":
		return r.handleToolsCall(ctx, msg)
	default:
		return r.handleForward(ctx, msg)
	}
}

// handleToolsList aggregates tools from all upstreams into a unified response.
func (r *UpstreamRouter) handleToolsList(msg *mcp.Message) (*mcp.Message, error) {
	allTools := r.toolCache.GetAllTools()

	// Sort tools by name for deterministic ordering.
	sort.Slice(allTools, func(i, j int) bool {
		return allTools[i].Name < allTools[j].Name
	})

	// Build the tools array for the response.
	tools := make([]toolEntry, 0, len(allTools))
	for _, t := range allTools {
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

	// Look up the tool in the cache.
	tool, found := r.toolCache.GetTool(toolName)
	if !found {
		r.logger.Warn("tool not found", "tool", toolName)
		return r.buildErrorResponse(msg, ErrCodeMethodNotFound, fmt.Sprintf("Tool not found: %s", toolName)), nil
	}

	r.logger.Debug("routing tools/call", "tool", toolName, "upstream", tool.UpstreamID)

	// Get connection to the upstream.
	writer, reader, err := r.manager.GetConnection(tool.UpstreamID)
	if err != nil {
		r.logger.Error("upstream connection failed", "upstream", tool.UpstreamID, "error", err)
		return r.buildErrorResponse(msg, ErrCodeInternal, fmt.Sprintf("Upstream unavailable: %s", tool.UpstreamID)), nil
	}

	return r.forwardToUpstream(msg, writer, reader)
}

// handleInitialize responds to the MCP initialize handshake directly.
// The proxy advertises its own capabilities (tools) without forwarding to upstreams.
func (r *UpstreamRouter) handleInitialize(msg *mcp.Message) (*mcp.Message, error) {
	r.logger.Debug("handling initialize locally")

	result := map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "sentinel-gate",
			"version": "1.0.0",
		},
	}

	return r.buildResultResponse(msg, result)
}

// handleForward forwards non-tool messages to the first available upstream.
func (r *UpstreamRouter) handleForward(ctx context.Context, msg *mcp.Message) (*mcp.Message, error) {
	r.logger.Debug("forwarding message to upstream", "method", msg.Method())

	// Find the first upstream that has tools (i.e. is connected).
	allTools := r.toolCache.GetAllTools()
	if len(allTools) > 0 {
		upstreamID := allTools[0].UpstreamID
		writer, reader, err := r.manager.GetConnection(upstreamID)
		if err == nil {
			return r.forwardToUpstream(msg, writer, reader)
		}
		r.logger.Error("upstream connection failed", "upstream", upstreamID, "error", err)
	}

	// Fallback: try legacy "primary" key (for single-upstream YAML mode).
	writer, reader, err := r.manager.GetConnection("primary")
	if err != nil {
		r.logger.Error("no upstream available for forwarding", "method", msg.Method(), "error", err)
		return r.buildErrorResponse(msg, ErrCodeNoUpstreams, "No upstream available"), nil
	}

	return r.forwardToUpstream(msg, writer, reader)
}

// forwardToUpstream writes the raw message to the upstream's stdin and reads the response.
func (r *UpstreamRouter) forwardToUpstream(msg *mcp.Message, writer io.WriteCloser, reader io.ReadCloser) (*mcp.Message, error) {
	// Write the raw message to upstream stdin (newline-delimited).
	data := msg.Raw
	if len(data) == 0 {
		return nil, fmt.Errorf("empty message to forward")
	}

	// Append newline if not already present.
	if data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("writing to upstream: %w", err)
	}

	// Read response from upstream stdout (newline-delimited JSON).
	scanner := bufio.NewScanner(reader)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("reading from upstream: %w", err)
		}
		return nil, fmt.Errorf("upstream closed connection without response")
	}

	responseBytes := scanner.Bytes()

	return &mcp.Message{
		Raw:       responseBytes,
		Direction: mcp.ServerToClient,
		Timestamp: time.Now(),
	}, nil
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

	// Set the ID if present.
	if rawID != nil {
		resp.ID = rawID
	}

	raw, err := json.Marshal(resp)
	if err != nil {
		r.logger.Error("failed to marshal error response", "error", err)
		return msg
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
	ID      json.RawMessage    `json:"id,omitempty"`
	Error   jsonRPCErrorDetail `json:"error"`
}

type jsonRPCErrorDetail struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

type jsonRPCResult struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result"`
}

type toolEntry struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type toolsListResult struct {
	Tools []toolEntry `json:"tools"`
}

// Compile-time check that UpstreamRouter implements MessageInterceptor.
var _ MessageInterceptor = (*UpstreamRouter)(nil)
