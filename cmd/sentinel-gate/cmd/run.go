package cmd

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/runtime"
)

var runCmd = &cobra.Command{
	Use:   "run -- <command> [args...]",
	Short: "Run an agent process with automatic security instrumentation",
	Long: `Run wraps any Python or Node.js agent process with SentinelGate's runtime
protection bootstrap. The bootstrap intercepts system calls (subprocess, file
access, network) and evaluates them against SentinelGate's policy engine before
allowing execution.

The run command:
  1. Detects the AI framework (LangChain, CrewAI, AutoGen, OpenAI Agents SDK)
  2. Generates a per-process API key for the agent
  3. Registers the key with the running SentinelGate server
  4. Creates a bootstrap directory with Python and Node.js hooks
  5. Sets SENTINELGATE_* environment variables on the child process
  6. Configures PYTHONPATH and NODE_OPTIONS for automatic instrumentation
  7. Auto-configures HTTP_PROXY/HTTPS_PROXY for Layer 2 outbound control
     When TLS inspection CA is available, also injects CA trust env vars
  8. For Bun-compiled binaries (e.g. Claude Code), auto-configures PreToolUse hooks
  9. For Gemini CLI, excludes native FS tools and routes file ops through MCP proxy
  10. Spawns the child process and propagates its exit code

The --fail-mode flag controls behavior when the SentinelGate server is unreachable:
  - "open" (default): allow actions, log a warning
  - "closed": deny all actions until the server is reachable

Examples:
  # Run a Python agent with SentinelGate protection
  sentinel-gate run -- python agent.py

  # Run a Node.js agent
  sentinel-gate run -- node agent.js

  # Run Claude Code with SentinelGate policy enforcement
  sentinel-gate run --fail-mode closed -- claude -p "do something"

  # Run Gemini CLI with SentinelGate (disables native FS tools, routes through MCP)
  sentinel-gate run -- gemini

  # Run with fail-closed mode (deny when server is unreachable)
  sentinel-gate run --fail-mode closed -- python agent.py

  # Run with custom server address
  sentinel-gate run --server-addr http://localhost:9090 -- python agent.py

  # Run with custom cache TTL
  sentinel-gate run --cache-ttl 10s -- python agent.py`,
	RunE:               runAgent,
	Args:               cobra.ArbitraryArgs,
	DisableFlagParsing: false,
}

var (
	runServerAddr string
	runCacheTTL   string
	runFailMode   string
)

func init() {
	runCmd.Flags().StringVar(&runServerAddr, "server-addr", "http://localhost:8080", "SentinelGate server address")
	runCmd.Flags().StringVar(&runCacheTTL, "cache-ttl", "5s", "LRU cache TTL for recently-allowed patterns")
	runCmd.Flags().StringVar(&runFailMode, "fail-mode", "open", "Behavior when SentinelGate server is unreachable: open (allow, log warning) or closed (deny all)")
	rootCmd.AddCommand(runCmd)
}

// runAgent is the entry point; it calls runAgentInternal (where defers run on return)
// and then propagates the exit code via os.Exit if needed.
func runAgent(cmd *cobra.Command, args []string) error {
	exitCode, err := runAgentInternal(args)
	if err != nil {
		return err
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
	return nil
}

// runAgentInternal contains the full run logic. All defers in this function
// execute before it returns, even when the child process exits non-zero.
func runAgentInternal(args []string) (exitCode int, retErr error) {
	// Step 1: Validate args — require at least one argument (the command to run).
	if len(args) == 0 {
		return 0, fmt.Errorf("no command specified; usage: sentinel-gate run -- <command> [args...]")
	}

	// Validate fail-mode value.
	if runFailMode != "open" && runFailMode != "closed" {
		return 0, fmt.Errorf("invalid fail-mode %q: must be 'open' or 'closed'", runFailMode)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Step 2: Detect AI framework from command and args.
	framework := runtime.DetectFramework(args[0], args[1:])
	if framework != "" {
		logger.Info("detected framework", "framework", framework)
	}

	// Step 2b: Detect Claude Code (Bun binary on macOS, npm wrapper on Windows).
	isClaude := runtime.IsClaudeCode(args[0])
	if isClaude {
		logger.Info("detected Claude Code, will use Claude Code hooks strategy", "command", args[0])
	}

	// Step 2c: Detect Gemini CLI for Gemini hooks strategy.
	isGemini := runtime.IsGeminiCLI(args[0])
	if isGemini {
		logger.Info("detected Gemini CLI, will use tools.exclude + MCP strategy", "command", args[0])
	}

	// Step 2d: If command is Python, detect site-packages paths so pip-installed
	// packages remain importable after we inject PYTHONPATH for bootstrap hooks.
	var pythonSitePackages []string
	if runtime.IsPythonCommand(args[0]) {
		pythonSitePackages = runtime.DetectPythonSitePackages(args[0])
		if len(pythonSitePackages) > 0 {
			logger.Info("detected Python site-packages", "paths", pythonSitePackages)
		}
	}

	// Step 2e: Ensure the SentinelGate server is running.
	// If not reachable, auto-start it as a background daemon.
	autoStarted, serverCleanup, autoErr := ensureServerRunning(runServerAddr, logger)
	if autoErr != nil {
		logger.Warn("failed to auto-start server, continuing anyway",
			"error", autoErr,
		)
	}
	if serverCleanup != nil {
		defer serverCleanup()
	}
	if autoStarted {
		logger.Info("server auto-started, will stop on exit",
			"server_addr", runServerAddr,
		)
	}

	// Step 3: Generate a local runtime API key (used as fallback if server is unreachable).
	localKey, _, err := runtime.GenerateRuntimeAPIKey()
	if err != nil {
		return 0, fmt.Errorf("failed to generate runtime API key: %w", err)
	}

	// Step 4: Generate agent ID.
	agentID := uuid.New().String()

	// Step 5: Register with the SentinelGate server.
	// If unreachable, fall back to local key and still run the child process.
	apiKey := localKey
	var regResult *registrationCleanup

	serverKey, result, regErr := runtime.RegisterRuntimeKey(runServerAddr, agentID)
	if regErr != nil {
		logger.Warn("SentinelGate server not reachable, using local key",
			"server_addr", runServerAddr,
			"fail_mode", runFailMode,
			"error", regErr,
		)
	} else {
		apiKey = serverKey
		regResult = &registrationCleanup{
			serverAddr: runServerAddr,
			identityID: result.IdentityID,
		}
		logger.Info("runtime key registered with server",
			"identity_id", result.IdentityID,
		)

		// Register the agent in the agent registry so it appears in the admin UI.
		agentReg := runtime.AgentRegistration{
			ID:        agentID,
			Command:   args[0],
			Args:      args[1:],
			Framework: framework,
			FailMode:  runFailMode,
			PID:       os.Getpid(),
		}
		if agentRegErr := runtime.RegisterAgent(runServerAddr, agentReg); agentRegErr != nil {
			logger.Warn("failed to register agent in registry", "error", agentRegErr)
		} else {
			logger.Info("agent registered in admin UI", "agent_id", agentID)
		}
	}

	// Step 6: Parse cache-ttl.
	cacheTTL, err := time.ParseDuration(runCacheTTL)
	if err != nil {
		return 0, fmt.Errorf("invalid cache-ttl %q: %w", runCacheTTL, err)
	}

	// Step 7: Determine CA cert path for TLS auto-setup.
	// If ~/.sentinelgate/ca-cert.pem exists, enable proxy auto-setup.
	var caCertPath string
	if homeDir, err := os.UserHomeDir(); err == nil {
		candidatePath := filepath.Join(homeDir, ".sentinelgate", "ca-cert.pem")
		if _, statErr := os.Stat(candidatePath); statErr == nil {
			caCertPath = candidatePath
			logger.Info("TLS inspection CA found, enabling proxy auto-setup", "ca_cert", caCertPath)
		}
	}

	// Step 8: Prepare bootstrap directory.
	// Skip NODE_OPTIONS for Claude Code (use PreToolUse hooks) and Gemini CLI
	// (uses MCP-level protection; NODE_OPTIONS would cause double interception
	// by catching Gemini's internal operations and user prompts before MCP tools
	// are even invoked).
	bootstrapCfg := runtime.BootstrapConfig{
		ServerAddr:         runServerAddr,
		APIKey:             apiKey,
		AgentID:            agentID,
		CacheTTL:           cacheTTL,
		FailMode:           runFailMode,
		Framework:          framework,
		CACertPath:         caCertPath,
		SkipNodeOptions:    isClaude || isGemini,
		PythonSitePackages: pythonSitePackages,
	}

	env, err := runtime.PrepareBootstrap(bootstrapCfg)
	if err != nil {
		return 0, fmt.Errorf("failed to prepare bootstrap: %w", err)
	}
	defer func() {
		if cleanErr := runtime.Cleanup(env); cleanErr != nil {
			logger.Warn("failed to cleanup bootstrap dir", "error", cleanErr)
		}
	}()

	// Step 9: Defer agent unregistration and runtime key revocation.
	if regResult != nil {
		defer func() {
			// Unregister agent from the admin UI registry.
			if unregErr := runtime.UnregisterAgent(regResult.serverAddr, agentID); unregErr != nil {
				logger.Warn("failed to unregister agent", "error", unregErr)
			} else {
				logger.Info("agent unregistered from admin UI", "agent_id", agentID)
			}

			// Revoke the runtime identity and API key.
			if revokeErr := runtime.RevokeRuntimeKey(regResult.serverAddr, regResult.identityID); revokeErr != nil {
				logger.Warn("failed to revoke runtime key", "error", revokeErr)
			} else {
				logger.Info("runtime key revoked", "identity_id", regResult.identityID)
			}
		}()
	}

	// Step 10: Build env vars and merge with parent environment.
	bootstrapVars := runtime.BuildEnvVars(env, bootstrapCfg)
	childEnv := runtime.MergeEnv(os.Environ(), bootstrapVars)

	// Step 10b: If Claude Code detected, set up PreToolUse hooks.
	// This writes ~/.claude/settings.json with a hook that invokes
	// "sentinel-gate claude-hook" for policy evaluation on every tool use.
	if isClaude {
		selfExe, err := os.Executable()
		if err != nil {
			return 0, fmt.Errorf("failed to resolve sentinel-gate executable path: %w", err)
		}
		hookSetup, err := runtime.SetupClaudeHooks(runtime.ClaudeHookConfig{
			SentinelGateExe: selfExe,
		})
		if err != nil {
			logger.Warn("failed to set up Claude Code hooks", "error", err)
		} else {
			logger.Info("Claude Code hooks configured", "settings_path", hookSetup.SettingsPath)
			defer func() {
				if cleanErr := runtime.CleanupClaudeHooks(hookSetup); cleanErr != nil {
					logger.Warn("failed to cleanup Claude Code hooks", "error", cleanErr)
				} else {
					logger.Info("Claude Code hooks cleaned up")
				}
			}()
		}
	}

	// Step 10d: If Gemini CLI detected, set up Gemini hooks.
	// This modifies ~/.gemini/settings.json to:
	//   1. Add SentinelGate as MCP server (httpUrl)
	//   2. Exclude native filesystem tools (forces MCP usage)
	if isGemini {
		hookSetup, err := runtime.SetupGeminiHooks(runtime.GeminiHookConfig{
			ServerAddr: runServerAddr,
			APIKey:     apiKey,
		})
		if err != nil {
			logger.Warn("failed to set up Gemini CLI hooks", "error", err)
		} else {
			logger.Info("Gemini CLI hooks configured",
				"settings_path", hookSetup.SettingsPath,
				"excluded_tools", "edit,replace,run_shell_command,grep_search,glob",
			)
			defer func() {
				if cleanErr := runtime.CleanupGeminiHooks(hookSetup); cleanErr != nil {
					logger.Warn("failed to cleanup Gemini CLI hooks", "error", cleanErr)
				} else {
					logger.Info("Gemini CLI hooks cleaned up")
				}
			}()
		}
	}

	// Step 10c: For Claude Code, remove the CLAUDECODE env var
	// to prevent the nested-session guard from blocking the child process.
	if isClaude {
		filtered := childEnv[:0]
		for _, v := range childEnv {
			if !strings.HasPrefix(v, "CLAUDECODE=") {
				filtered = append(filtered, v)
			}
		}
		childEnv = filtered
	}

	// Step 11: Create and configure the child process.
	childCmd := exec.Command(args[0], args[1:]...)
	childCmd.Env = childEnv
	childCmd.Stdin = os.Stdin
	childCmd.Stdout = os.Stdout
	childCmd.Stderr = os.Stderr

	// Step 12: Log startup info.
	logger.Info("starting agent process",
		"agent_id", agentID,
		"command", args[0],
		"args", args[1:],
		"server_addr", runServerAddr,
		"fail_mode", runFailMode,
		"framework", framework,
		"cache_ttl", cacheTTL.String(),
		"bootstrap_dir", env.Dir,
	)

	// Step 13: Start child process, forward signals, wait for exit.
	// Using Start+Wait instead of Run so that SIGINT/SIGTERM are handled
	// gracefully and defers (agent unregistration, key revocation) execute.

	// Ignore SIGINT/SIGTERM in the parent — the child gets them directly
	// from the terminal. We wait for the child to exit, then run defers.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, gracefulSignals()...)
	defer signal.Stop(sigCh)

	if err := childCmd.Start(); err != nil {
		logger.Error("failed to start agent process", "error", err)
		return 1, nil
	}

	// Drain signals in background (don't let them kill us).
	go func() {
		for range sigCh {
			// Child process receives signals from the terminal directly.
			// Parent ignores them and waits for child to exit.
		}
	}()

	waitErr := childCmd.Wait()
	signal.Stop(sigCh)

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		logger.Error("agent process failed", "error", waitErr)
		return 1, nil
	}

	return 0, nil
}

// registrationCleanup holds the information needed to revoke a runtime key on exit.
type registrationCleanup struct {
	serverAddr string
	identityID string
}

// ensureServerRunning checks if the SentinelGate server is reachable.
// If not, it auto-starts the server as a background daemon process.
//
// Returns:
//   - autoStarted: true if this call started the server
//   - cleanup: function to stop the server on exit (nil if server was already running)
//   - err: non-fatal error (caller should continue even if auto-start fails)
func ensureServerRunning(serverAddr string, logger *slog.Logger) (autoStarted bool, cleanup func(), err error) {
	// Check if server is already running.
	if isServerHealthy(serverAddr) {
		return false, nil, nil
	}

	logger.Info("server not running, auto-starting...", "server_addr", serverAddr)

	// Find our own executable to run "sentinel-gate start".
	selfExe, err := os.Executable()
	if err != nil {
		return false, nil, fmt.Errorf("failed to resolve executable path: %w", err)
	}

	// Ensure log directory exists.
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return false, nil, fmt.Errorf("failed to get home dir: %w", err)
	}
	sgDir := filepath.Join(homeDir, ".sentinelgate")
	if mkErr := os.MkdirAll(sgDir, 0755); mkErr != nil {
		return false, nil, fmt.Errorf("failed to create .sentinelgate dir: %w", mkErr)
	}

	// Open log file for the daemon's stdout/stderr.
	logPath := filepath.Join(sgDir, "server.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return false, nil, fmt.Errorf("failed to open server log %s: %w", logPath, err)
	}

	// Start "sentinel-gate start" as a detached background process.
	cmd := exec.Command(selfExe, "start")
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Dir = func() string {
		// Use current working directory so the server finds the same
		// config files and state.json as a manual "sentinel-gate start".
		if wd, wdErr := os.Getwd(); wdErr == nil {
			return wd
		}
		return homeDir
	}()

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return false, nil, fmt.Errorf("failed to start server process: %w", err)
	}
	logFile.Close()

	serverPID := cmd.Process.Pid
	logger.Info("server process started", "pid", serverPID, "log", logPath)

	// Wait for the server to become healthy (poll /health every 500ms, max 15s).
	healthy := false
	for i := 0; i < 30; i++ {
		time.Sleep(500 * time.Millisecond)
		if isServerHealthy(serverAddr) {
			healthy = true
			break
		}
	}

	if !healthy {
		// Server didn't start in time — kill it and report failure.
		_ = sendGracefulStop(cmd.Process)
		return false, nil, fmt.Errorf("server did not become healthy within 15s (check %s)", logPath)
	}

	logger.Info("server is healthy")

	// Return a cleanup function that stops the server when the agent exits.
	cleanupFn := func() {
		logger.Info("stopping auto-started server", "pid", serverPID)
		if killErr := sendGracefulStop(cmd.Process); killErr != nil {
			logger.Warn("failed to stop server", "error", killErr)
			return
		}
		// Wait briefly for the process to exit.
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
			logger.Info("server stopped")
		case <-time.After(5 * time.Second):
			logger.Warn("server did not stop in 5s, killing")
			_ = cmd.Process.Kill()
		}
	}

	return true, cleanupFn, nil
}

// isServerHealthy checks if the SentinelGate server is reachable by hitting /health.
func isServerHealthy(serverAddr string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(serverAddr + "/health")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// readPIDFile reads a PID from the given file path. Returns 0 if unreadable.
func readPIDFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}
