// Package inbound defines the inbound port interfaces for the proxy core.
// Inbound adapters (stdio, HTTP) call these interfaces.
package inbound

import (
	"context"
)

// ProxyService is the inbound port for the proxy core.
// Inbound adapters (stdio, HTTP) call this interface.
type ProxyService interface {
	// Start begins proxying between client and upstream server.
	// Blocks until context is cancelled or an error occurs.
	// Returns nil on graceful shutdown, error on failure.
	Start(ctx context.Context) error

	// Close gracefully shuts down the proxy and cleans up resources.
	Close() error
}
