// Package stdio provides the stdio transport adapter for the proxy.
package stdio

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/inbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// StdioTransport is the inbound adapter that connects the proxy to stdin/stdout.
// It implements the inbound.ProxyService interface.
type StdioTransport struct {
	proxyService *service.ProxyService
	mu           sync.Mutex
}

// NewStdioTransport creates a stdio transport adapter wrapping the given proxy service.
func NewStdioTransport(proxyService *service.ProxyService) *StdioTransport {
	return &StdioTransport{
		proxyService: proxyService,
	}
}

// Start begins proxying between stdin/stdout and the upstream server.
// It blocks until the context is cancelled or an error occurs.
// This method reads from os.Stdin and writes to os.Stdout.
func (t *StdioTransport) Start(ctx context.Context) error {
	// For stdio transport, use "local" as IP address (no real remote IP).
	// This ensures all stdio connections share one rate limit bucket.
	ctx = context.WithValue(ctx, proxy.IPAddressKey, "local")
	return t.proxyService.Run(ctx, os.Stdin, os.Stdout)
}

// SendNotification writes a JSON-RPC notification to stdout.
// The entire message (including trailing newline) is written in a single
// Write call to ensure atomicity on POSIX pipes (payload < PIPE_BUF).
func (t *StdioTransport) SendNotification(method string) {
	notification := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
	}
	data, err := json.Marshal(notification)
	if err != nil {
		return
	}
	// Append newline for line-delimited JSON-RPC and write atomically.
	data = append(data, '\n')
	t.mu.Lock()
	_, _ = os.Stdout.Write(data)
	t.mu.Unlock()
}

// Close gracefully shuts down the transport.
// For stdio, there are no resources to clean up.
func (t *StdioTransport) Close() error {
	return nil
}

// Compile-time check that StdioTransport implements ProxyService interface.
var _ inbound.ProxyService = (*StdioTransport)(nil)
