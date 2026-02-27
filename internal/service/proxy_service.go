// Package service contains the core proxy service implementation.
package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/ctxkey"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/validation"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// loggerFromContext retrieves the enriched logger from context.
// Uses the same key as HTTP middleware for request_id/tenant_id enrichment.
// Returns nil if no logger is in context, allowing caller to fall back.
func loggerFromContext(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(ctxkey.LoggerKey{}).(*slog.Logger); ok {
		return logger
	}
	return nil
}

// ProxyService orchestrates bidirectional message proxying between
// the client and the upstream MCP server.
type ProxyService struct {
	client      outbound.MCPClient
	interceptor proxy.MessageInterceptor
	logger      *slog.Logger
}

// NewProxyService creates a new proxy service with the given dependencies.
func NewProxyService(client outbound.MCPClient, interceptor proxy.MessageInterceptor, logger *slog.Logger) *ProxyService {
	return &ProxyService{
		client:      client,
		interceptor: interceptor,
		logger:      logger,
	}
}

// Run starts the bidirectional proxy between client and upstream server.
// It blocks until the context is cancelled or an error occurs.
// clientIn is where we read messages from (typically os.Stdin).
// clientOut is where we write messages to (typically os.Stdout).
//
// When client is nil (multi-upstream mode), the interceptor chain handles all
// routing via the UpstreamRouter. Messages are processed through the interceptor
// and responses are written back to clientOut without needing an upstream pipe.
func (p *ProxyService) Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer) error {
	// Use enriched logger from context if available (includes request_id, tenant_id)
	logger := loggerFromContext(ctx)
	if logger == nil {
		logger = p.logger
	}

	// Router-only mode: no direct upstream client, interceptor chain handles everything.
	// The UpstreamRouter interceptor routes tools/list and tools/call to the correct
	// upstream via UpstreamConnectionProvider, flipping message direction to ServerToClient.
	if p.client == nil {
		return p.runRouterOnly(ctx, clientIn, clientOut, logger)
	}

	// Start the upstream server and get its stdio pipes
	serverIn, serverOut, err := p.client.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start upstream server: %w", err)
	}
	defer func() { _ = p.client.Close() }()

	// Create cancellable context for goroutines
	// Save parent context to distinguish external cancellation from normal termination
	parentCtx := ctx
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	// Goroutine 1: client -> server (requests)
	// Pass clientOut for error responses when interceptor rejects
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = serverIn.Close() }() // Signal EOF to server when client disconnects
		if err := p.copyMessages(ctx, clientIn, serverIn, clientOut, mcp.ClientToServer, logger); err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				errCh <- fmt.Errorf("client->server: %w", err)
			}
		}
		logger.Debug("client->server copy completed")
	}()

	// Goroutine 2: server -> client (responses)
	// No error responses needed for server->client direction
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := p.copyMessages(ctx, serverOut, clientOut, nil, mcp.ServerToClient, logger); err != nil {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				errCh <- fmt.Errorf("server->client: %w", err)
			}
		}
		logger.Debug("server->client copy completed")
		cancel() // Server closed, cancel everything
	}()

	// Wait for both goroutines to finish
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	// Wait for completion or error
	select {
	case <-done:
		// Both goroutines finished
	case err := <-errCh:
		cancel() // Cancel remaining work
		<-done   // Wait for cleanup
		return err
	}

	// Wait for upstream process to finish
	if err := p.client.Wait(); err != nil {
		// Ignore expected errors when context was cancelled
		if parentCtx.Err() == nil {
			logger.Debug("upstream server exited", "error", err)
		}
	}

	// Return parent context error only if external cancellation occurred.
	// If termination was normal (we called cancel() ourselves at line 80),
	// parentCtx.Err() will be nil.
	return parentCtx.Err()
}

// runRouterOnly handles the case where there is no direct upstream client.
// All messages are processed through the interceptor chain, which is expected
// to handle routing (via UpstreamRouter) and return responses by flipping
// the message direction from ClientToServer to ServerToClient.
func (p *ProxyService) runRouterOnly(ctx context.Context, clientIn io.Reader, clientOut io.Writer, logger *slog.Logger) error {
	logger.Debug("running in router-only mode (no direct upstream client)")
	return p.copyMessages(ctx, clientIn, io.Discard, clientOut, mcp.ClientToServer, logger)
}

// copyMessages reads newline-delimited JSON messages from src,
// passes them through the interceptor, and writes to dst.
// clientOut is used to send error responses back to client when interceptor rejects
// (only for ClientToServer direction, nil for ServerToClient).
// logger is the context-enriched logger with request_id/tenant_id fields.
func (p *ProxyService) copyMessages(ctx context.Context, src io.Reader, dst io.Writer, clientOut io.Writer, direction mcp.Direction, logger *slog.Logger) error {
	// Use large buffer for scanner (MCP messages can be large)
	// Per MCP spec, messages are newline-delimited JSON
	scanner := bufio.NewScanner(src)
	buf := make([]byte, 0, 256*1024) // 256KB initial
	scanner.Buffer(buf, 1024*1024)   // 1MB max

	for scanner.Scan() {
		// Check context before processing
		if ctx.Err() != nil {
			return ctx.Err()
		}

		startTime := time.Now()
		raw := scanner.Bytes()

		// Create message wrapper with metadata
		msg := &mcp.Message{
			Raw:       append([]byte(nil), raw...), // Copy bytes
			Direction: direction,
			Timestamp: startTime,
		}

		// Attempt to decode for inspection (non-fatal if fails)
		if decoded, err := mcp.DecodeMessage(raw); err == nil {
			msg.Decoded = decoded

			// Parse params once for client->server requests (reused by interceptors)
			if direction == mcp.ClientToServer {
				_ = msg.ParseParams() // Ignore error, ParsedParams will be nil if fails
			}
		} else {
			logger.Debug("failed to decode message, passing through raw",
				"direction", direction,
				"error", err,
			)
		}

		// Pass through interceptor
		processedMsg, err := p.interceptor.Intercept(ctx, msg)
		if err != nil {
			logger.Error("interceptor rejected message",
				"direction", direction,
				"error", err,
			)
			// Send error response for client->server (requests only)
			// Server->client errors should not loop back
			if direction == mcp.ClientToServer && clientOut != nil {
				// Use RawID to preserve the original ID format (SDK's ID type
				// doesn't marshal correctly through interface{})
				rawID := msg.RawID()
				code := -32600
				// SECURITY: Use SafeErrorMessage to sanitize client-facing errors.
				// Internal error details are logged above but not exposed to clients.
				message := proxy.SafeErrorMessage(err)
				var valErr *validation.ValidationError
				if errors.As(err, &valErr) {
					code = valErr.Code
					message = valErr.Message
				}
				errResp := proxy.CreateJSONRPCError(rawID, code, message)
				_, _ = clientOut.Write(errResp)
				_, _ = clientOut.Write([]byte("\n"))
				logger.Debug("sent error response to client", "safe_message", message)
			}
			continue
		}

		// Determine write target. If the interceptor chain produced a final response
		// (direction changed from ClientToServer to ServerToClient), send it back to
		// the client instead of forwarding to the upstream. This handles the case
		// where the upstream router generates tools/list or tools/call responses
		// directly from the tool cache without needing the upstream.
		writeTo := dst
		if direction == mcp.ClientToServer && processedMsg.Direction == mcp.ServerToClient && clientOut != nil {
			writeTo = clientOut
		}

		// Write message followed by newline
		if _, err := writeTo.Write(processedMsg.Raw); err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		if _, err := writeTo.Write([]byte("\n")); err != nil {
			return fmt.Errorf("write newline failed: %w", err)
		}

		// Log latency
		latency := time.Since(startTime)
		logger.Debug("forwarded message",
			"direction", direction,
			"method", processedMsg.Method(),
			"latency_us", latency.Microseconds(),
		)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan error: %w", err)
	}

	return nil
}
