// Package outbound defines the outbound port interfaces for connecting
// to upstream MCP servers.
package outbound

import (
	"context"
	"io"
)

// MCPClient is the outbound port for connecting to upstream MCP servers.
// Adapters implement this to support different transports (stdio, HTTP).
type MCPClient interface {
	// Start launches the upstream MCP server connection.
	// Returns the server's stdin (for sending) and stdout (for receiving).
	Start(ctx context.Context) (stdin io.WriteCloser, stdout io.ReadCloser, err error)

	// Wait blocks until the upstream server process/connection terminates.
	// Returns nil on graceful shutdown, error on failure.
	Wait() error

	// Close terminates the upstream connection and cleans up resources.
	Close() error
}
