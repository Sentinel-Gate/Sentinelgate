// Package cmd provides the CLI commands for Sentinel Gate.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
	"github.com/Sentinel-Gate/Sentinelgate/internal/lifecycle"
)

var startCmd = &cobra.Command{
	Use:   "start [-- command [args...]]",
	Short: "Start the proxy server",
	Long: `Start the Sentinel Gate proxy server.

The proxy can operate in two modes:

1. HTTP mode: Connect to a remote MCP server via HTTP
   Configure upstream.http in your config file.

2. Stdio mode: Spawn an MCP server as a subprocess
   Configure upstream.command in your config file, or pass command after --.

Examples:
  # Start with config file settings
  sentinel-gate start

  # Start with a specific MCP server command
  sentinel-gate start -- npx @modelcontextprotocol/server-filesystem /tmp

  # Start with a specific config file
  sentinel-gate --config /path/to/config.yaml start`,
	RunE: runStart,
}

func init() {
	rootCmd.AddCommand(startCmd)
}

func runStart(cmd *cobra.Command, args []string) error {
	// Load configuration (without validation, so CLI flags can override first)
	cfg, err := config.LoadConfigRaw()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Stdio transport is used ONLY when the user explicitly passes "-- command [args]".
	stdioTransport := len(args) > 0

	// Override upstream command from args if provided
	if len(args) > 0 {
		cfg.Upstream.HTTP = ""
		cfg.Upstream.Command = args[0]
		if len(args) > 1 {
			cfg.Upstream.Args = args[1:]
		} else {
			cfg.Upstream.Args = nil
		}
	}

	// Validate the configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Resolve state file path: CLI flag > env var > default
	statePath := stateFilePath
	if statePath == "" {
		statePath = os.Getenv("SENTINEL_GATE_STATE_PATH")
	}
	if statePath == "" {
		statePath = "./state.json"
	}
	// L-45: Convert to absolute path early so storage does not depend on cwd.
	if absPath, err := filepath.Abs(statePath); err == nil {
		statePath = absPath
	}

	// Create signal context for graceful shutdown.
	// L-46: defer stop() to cancel the context when runStart returns,
	// preventing the goroutine from leaking if run() errors before a signal.
	ctx, stop := signal.NotifyContext(context.Background(), gracefulSignals()...)
	defer stop()
	go func() {
		<-ctx.Done()
		stop() // Restore default: next Ctrl+C = immediate exit.
	}()

	// Setup logger to stderr (stdout reserved for MCP stream in stdio mode)
	logLevel := parseLogLevel(cfg.Server.LogLevel)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
	logger.Debug("log level configured", "level", cfg.Server.LogLevel, "effective", logLevel.String())

	if configFile := config.ConfigFileUsed(); configFile != "" {
		logger.Info("loaded config", "file", configFile)
	}

	// Write PID file
	pidPath := pidFilePath()
	if err := writePIDFile(pidPath); err != nil {
		logger.Warn("failed to write PID file", "path", pidPath, "error", err)
	} else {
		defer os.Remove(pidPath)
	}

	// Run the proxy
	if err := run(ctx, cfg, statePath, stdioTransport, logger); err != nil {
		return err
	}

	logger.Info("sentinel-gate stopped")
	return nil
}

// run is the main orchestration function that wires all components together.
// It delegates to bootContext methods for each phase (A1 decomposition).
// Boot sequence: BOOT-00 through BOOT-09.
func run(ctx context.Context, cfg *config.OSSConfig, statePath string, stdioTransport bool, logger *slog.Logger) error {
	bc := &bootContext{
		cfg:       cfg,
		statePath: statePath,
		logger:    logger,
		startTime: time.Now().UTC(),
		lifecycle: lifecycle.NewManager(logger),
	}
	defer bc.runCleanups()
	defer func() {
		// Ordered shutdown via lifecycle manager (A6)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := bc.lifecycle.Shutdown(shutdownCtx); err != nil {
			logger.Error("lifecycle shutdown errors", "error", err)
		}
	}()

	// BOOT-03/04: Stores + seeding
	if err := bc.bootStores(ctx); err != nil {
		return err
	}

	// Services layer
	if err := bc.bootServices(ctx); err != nil {
		return err
	}

	// BOOT-05/06: Upstreams + tool discovery
	if err := bc.bootUpstreams(ctx); err != nil {
		return err
	}

	// Admin API handler
	bc.bootAdminAPI()

	// BOOT-07: Interceptor chain (+ recording, quota, rate limiting)
	if err := bc.bootInterceptorChain(ctx); err != nil {
		return err
	}

	// Compliance + Simulation services (Upgrade 2, UX-F1)
	// Must be wired AFTER bootAdminAPI + bootInterceptorChain since they
	// reference apiHandler and interceptor fields.
	bc.bootComplianceAndSimulation()

	// Start periodic budget check AFTER finopsService is created
	// (finopsService is wired in bootComplianceAndSimulation).
	if bc.finopsService != nil {
		bc.finopsService.StartPeriodicBudgetCheck(ctx, 2*time.Minute)
	}

	// Validate all critical components are wired
	if err := bc.validate(); err != nil {
		return err
	}

	// BOOT-08: Create proxy service
	bc.bootTransport()

	// BOOT-09: Start transport
	return bc.startTransport(ctx, stdioTransport)
}

// pidFilePath returns the standard location for the SentinelGate PID file.
func pidFilePath() string {
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".sentinelgate", "server.pid")
	}
	return filepath.Join(os.TempDir(), "sentinelgate-server.pid")
}

// writePIDFile writes the current process PID to the given path, creating
// parent directories as needed.
func writePIDFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0600)
}
