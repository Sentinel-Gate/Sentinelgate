// Package mcp provides MCP client adapters for connecting to upstream servers.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
)

// StdioClient connects to an MCP server via stdio (subprocess).
// It implements the outbound.MCPClient interface.
type StdioClient struct {
	serverPath string
	serverArgs []string

	mu     sync.Mutex
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

// NewStdioClient creates a client for the given MCP server command.
// The serverPath is the executable to run, and serverArgs are passed to it.
func NewStdioClient(serverPath string, serverArgs ...string) *StdioClient {
	return &StdioClient{
		serverPath: serverPath,
		serverArgs: serverArgs,
	}
}

// Start launches the upstream MCP server as a subprocess.
// Returns the server's stdin (for sending) and stdout (for receiving).
// The server's stderr is forwarded to os.Stderr (MCP spec allows server logging).
func (c *StdioClient) Start(ctx context.Context) (io.WriteCloser, io.ReadCloser, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cmd != nil {
		return nil, nil, errors.New("client already started")
	}

	// Use CommandContext for cancellation support
	c.cmd = exec.CommandContext(ctx, c.serverPath, c.serverArgs...)

	// Get pipes for stdin and stdout
	stdin, err := c.cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	c.stdin = stdin

	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	c.stdout = stdout

	// Forward server stderr to proxy stderr (MCP spec allows server logging)
	c.cmd.Stderr = os.Stderr

	// Start the subprocess
	if err := c.cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		c.cmd = nil
		return nil, nil, fmt.Errorf("failed to start server: %w", err)
	}

	return stdin, stdout, nil
}

// Wait blocks until the upstream server process terminates.
// Returns nil on graceful shutdown, error on failure.
func (c *StdioClient) Wait() error {
	c.mu.Lock()
	cmd := c.cmd
	c.mu.Unlock()

	if cmd == nil {
		return errors.New("client not started")
	}

	return cmd.Wait()
}

// Close terminates the upstream connection and cleans up resources.
// It kills the process if still running and closes all pipes.
func (c *StdioClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error

	// Close stdin first to signal EOF to server
	if c.stdin != nil {
		if err := c.stdin.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close stdin: %w", err))
		}
		c.stdin = nil
	}

	// Kill process if still running
	if c.cmd != nil && c.cmd.Process != nil {
		if err := c.cmd.Process.Kill(); err != nil {
			// Ignore "process already finished" errors
			if !errors.Is(err, os.ErrProcessDone) {
				errs = append(errs, fmt.Errorf("kill process: %w", err))
			}
		}
	}
	c.cmd = nil

	// Close stdout
	if c.stdout != nil {
		if err := c.stdout.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close stdout: %w", err))
		}
		c.stdout = nil
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// Compile-time check that StdioClient implements MCPClient interface.
var _ outbound.MCPClient = (*StdioClient)(nil)
