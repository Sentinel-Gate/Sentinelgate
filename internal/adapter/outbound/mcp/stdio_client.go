// Package mcp provides MCP client adapters for connecting to upstream servers.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
)

// sensitiveEnvKeys lists environment variable names that must not be
// forwarded to MCP subprocess servers.
var sensitiveEnvKeys = map[string]bool{
	// AWS
	"AWS_SECRET_ACCESS_KEY": true,
	"AWS_ACCESS_KEY_ID":     true,
	"AWS_SESSION_TOKEN":     true,
	// GCP / Azure
	"GOOGLE_APPLICATION_CREDENTIALS": true,
	"AZURE_CLIENT_SECRET":            true,
	// Database
	"DATABASE_URL": true,
	"DB_PASSWORD":  true,
	// VCS tokens
	"GITHUB_TOKEN": true,
	"GH_TOKEN":     true,
	"GITLAB_TOKEN": true,
	// AI provider keys
	"OPENAI_API_KEY":    true,
	"ANTHROPIC_API_KEY": true,
	// Payment
	"STRIPE_SECRET_KEY": true,
	// Generic secrets
	"API_SECRET":  true,
	"SECRET_KEY":  true,
	"PRIVATE_KEY": true,
}

// sensitiveKeyPatterns are substrings that, when found in an env var name
// (case-insensitive), indicate the variable likely contains a secret.
// M-50: heuristic filtering catches keys not in the explicit blocklist.
var sensitiveKeyPatterns = []string{
	"SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY", "API_KEY",
}

// isSensitiveKey returns true if the key is explicitly blocked or matches
// a heuristic pattern indicating it likely contains a secret.
func isSensitiveKey(key string) bool {
	if sensitiveEnvKeys[key] {
		return true
	}
	upper := strings.ToUpper(key)
	for _, pat := range sensitiveKeyPatterns {
		if strings.Contains(upper, pat) {
			return true
		}
	}
	return false
}

// sanitizedEnviron returns os.Environ() with sensitive keys removed.
func sanitizedEnviron() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		key, _, _ := strings.Cut(e, "=")
		if !isSensitiveKey(key) {
			env = append(env, e)
		}
	}
	return env
}

// StdioClient connects to an MCP server via stdio (subprocess).
// It implements the outbound.MCPClient interface.
type StdioClient struct {
	serverPath string
	serverArgs []string
	serverEnv  map[string]string

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

// SetEnv sets custom environment variables for the subprocess.
// These are merged with the parent process environment.
func (c *StdioClient) SetEnv(env map[string]string) {
	c.serverEnv = env
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

	// Always use sanitized environment to prevent leaking secrets to
	// subprocess MCP servers. Custom env vars are merged on top.
	c.cmd.Env = sanitizedEnviron()
	for k, v := range c.serverEnv {
		c.cmd.Env = append(c.cmd.Env, k+"="+v)
	}

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
