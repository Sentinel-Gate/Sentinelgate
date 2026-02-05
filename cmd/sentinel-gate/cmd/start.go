// Package cmd provides the CLI commands for Sentinel Gate.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/admin"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/http"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/stdio"
	mcpclient "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/mcp"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
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
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override upstream command from args if provided
	if len(args) > 0 {
		cfg.Upstream.Command = args[0]
		if len(args) > 1 {
			cfg.Upstream.Args = args[1:]
		} else {
			cfg.Upstream.Args = nil
		}
	}

	// Validate: either upstream.http OR upstream.command required
	if cfg.Upstream.HTTP == "" && cfg.Upstream.Command == "" {
		return fmt.Errorf("upstream configuration required: set upstream.http or upstream.command in config, or pass command after --")
	}

	// Create signal context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Setup logger to stderr (stdout reserved for MCP stream in stdio mode)
	// Priority: DevMode=true -> debug, otherwise use configured log_level
	logLevel := parseLogLevel(cfg.Server.LogLevel)
	if cfg.DevMode {
		logLevel = slog.LevelDebug // DevMode always forces debug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: logLevel,
	}))
	logger.Debug("log level configured", "level", cfg.Server.LogLevel, "effective", logLevel.String())

	// Log config file used if any
	if configFile := config.ConfigFileUsed(); configFile != "" {
		logger.Info("loaded config", "file", configFile)
	}

	// Run the proxy
	if err := run(ctx, cfg, logger); err != nil {
		return err
	}

	logger.Info("sentinel-gate stopped")
	return nil
}

// run is the main orchestration function that wires all components together.
func run(ctx context.Context, cfg *config.OSSConfig, logger *slog.Logger) error {
	// Check DevMode and log warning (or block startup if blocked by env var)
	if err := proxy.LogDevModeWarning(logger, cfg.DevMode); err != nil {
		return err
	}

	// Initialize memory stores
	authStore := memory.NewAuthStore()
	sessionStore := memory.NewSessionStore()
	sessionStore.StartCleanup(ctx)
	defer sessionStore.Stop()
	policyStore := memory.NewPolicyStore()
	var rateLimiter *memory.MemoryRateLimiter

	// Seed auth from config
	if err := seedAuthFromConfig(cfg, authStore); err != nil {
		return fmt.Errorf("failed to seed auth: %w", err)
	}
	logger.Debug("seeded auth from config",
		"identities", len(cfg.Auth.Identities),
		"api_keys", len(cfg.Auth.APIKeys),
	)

	// Seed policies from config
	if err := seedPoliciesFromConfig(cfg, policyStore); err != nil {
		return fmt.Errorf("failed to seed policies: %w", err)
	}
	logger.Debug("seeded policies from config", "policies", len(cfg.Policies))

	// Parse session timeout from config
	sessionTimeout, err := time.ParseDuration(cfg.Server.SessionTimeout)
	if err != nil {
		sessionTimeout = 30 * time.Minute // fallback to default
		logger.Warn("invalid session_timeout, using default",
			"value", cfg.Server.SessionTimeout, "default", "30m")
	}

	// Create services
	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{
		Timeout: sessionTimeout,
	})
	policyService, err := service.NewPolicyService(policyStore, logger)
	if err != nil {
		return fmt.Errorf("failed to create policy service: %w", err)
	}

	// Create audit store
	auditStore, err := createAuditStore(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to create audit store: %w", err)
	}
	defer auditStore.Close()

	// Parse duration strings from audit config
	flushInterval, err := time.ParseDuration(cfg.Audit.FlushInterval)
	if err != nil {
		flushInterval = time.Second // fallback to default
		logger.Warn("invalid flush_interval, using default", "value", cfg.Audit.FlushInterval, "default", "1s")
	}

	sendTimeout, err := time.ParseDuration(cfg.Audit.SendTimeout)
	if err != nil {
		sendTimeout = 100 * time.Millisecond // fallback to default
		logger.Warn("invalid send_timeout, using default", "value", cfg.Audit.SendTimeout, "default", "100ms")
	}

	// Create audit service with config values
	auditService := service.NewAuditService(auditStore, logger,
		service.WithChannelSize(cfg.Audit.ChannelSize),
		service.WithBatchSize(cfg.Audit.BatchSize),
		service.WithFlushInterval(flushInterval),
		service.WithSendTimeout(sendTimeout),
		service.WithWarningThreshold(cfg.Audit.WarningThreshold),
	)
	auditService.Start(ctx)
	defer auditService.Stop()

	// Build interceptor chain (inner to outer)
	// Order: passthrough (innermost) -> policy -> audit -> auth -> ratelimit (optional) -> validation (outermost)
	passthrough := proxy.NewPassthroughInterceptor()
	policyInterceptor := proxy.NewPolicyInterceptor(policyService, passthrough, logger)
	auditInterceptor := proxy.NewAuditInterceptor(auditService, policyInterceptor, logger)
	authInterceptor := proxy.NewAuthInterceptor(apiKeyService, sessionService, auditInterceptor, logger, cfg.DevMode)
	authInterceptor.StartCleanup(ctx)
	defer authInterceptor.Stop()

	var chainHead proxy.MessageInterceptor = authInterceptor

	// Add rate limiting if enabled
	if cfg.RateLimit.Enabled {
		// Parse cleanup interval
		cleanupInterval, err := time.ParseDuration(cfg.RateLimit.CleanupInterval)
		if err != nil {
			cleanupInterval = 5 * time.Minute
			logger.Warn("invalid rate_limit.cleanup_interval, using default",
				"value", cfg.RateLimit.CleanupInterval, "default", "5m")
		}

		// Parse max TTL
		maxTTL, err := time.ParseDuration(cfg.RateLimit.MaxTTL)
		if err != nil {
			maxTTL = 1 * time.Hour
			logger.Warn("invalid rate_limit.max_ttl, using default",
				"value", cfg.RateLimit.MaxTTL, "default", "1h")
		}

		// Create rate limiter with config values
		rateLimiter = memory.NewRateLimiterWithConfig(cleanupInterval, maxTTL)

		ipConfig := ratelimit.RateLimitConfig{
			Rate:   cfg.RateLimit.IPRate,
			Burst:  cfg.RateLimit.IPRate,
			Period: time.Minute,
		}
		userConfig := ratelimit.RateLimitConfig{
			Rate:   cfg.RateLimit.UserRate,
			Burst:  cfg.RateLimit.UserRate,
			Period: time.Minute,
		}
		chainHead = proxy.NewRateLimitInterceptor(rateLimiter, ipConfig, userConfig, authInterceptor, logger)
		logger.Debug("rate limiting enabled",
			"ip_rate", cfg.RateLimit.IPRate,
			"user_rate", cfg.RateLimit.UserRate,
			"cleanup_interval", cleanupInterval,
			"max_ttl", maxTTL,
		)
	} else {
		// Create with defaults even if disabled (needed for health checker)
		rateLimiter = memory.NewRateLimiter()
	}

	// Start rate limiter cleanup
	rateLimiter.StartCleanup(ctx)
	defer rateLimiter.Stop()

	// Validation interceptor is always outermost
	validationInterceptor := proxy.NewValidationInterceptor(chainHead, logger)

	// Parse HTTP timeout for upstream client
	httpTimeout, err := time.ParseDuration(cfg.Upstream.HTTPTimeout)
	if err != nil {
		httpTimeout = 30 * time.Second // fallback to default
		logger.Warn("invalid http_timeout, using default",
			"value", cfg.Upstream.HTTPTimeout, "default", "30s")
	}

	// Create MCP client
	var mcpClient outbound.MCPClient
	if cfg.Upstream.HTTP != "" {
		mcpClient = mcpclient.NewHTTPClient(cfg.Upstream.HTTP,
			mcpclient.WithTimeout(httpTimeout))
		logger.Info("upstream mode: HTTP", "endpoint", cfg.Upstream.HTTP, "timeout", httpTimeout)
	} else {
		mcpClient = mcpclient.NewStdioClient(cfg.Upstream.Command, cfg.Upstream.Args...)
		logger.Info("upstream mode: stdio", "command", cfg.Upstream.Command, "args", cfg.Upstream.Args)
	}

	// Create proxy service
	proxyService := service.NewProxyService(mcpClient, validationInterceptor, logger)

	// Log startup info
	logger.Info("sentinel-gate starting",
		"dev_mode", cfg.DevMode,
		"rate_limit_enabled", cfg.RateLimit.Enabled,
		"audit_output", cfg.Audit.Output,
	)

	// Select and start transport
	// Stdio transport is used when upstream is a command (subprocess)
	// HTTP transport is used when upstream is an HTTP endpoint
	if cfg.Upstream.Command != "" {
		// Stdio transport mode - used with subprocess MCP servers
		transport := stdio.NewStdioTransport(proxyService)
		logger.Info("transport mode: stdio")
		return transport.Start(ctx)
	}

	// HTTP transport mode - used with remote HTTP MCP servers
	// Create admin UI handler
	adminHandler, err := admin.NewAdminHandler(cfg, logger)
	if err != nil {
		logger.Warn("failed to create admin handler, UI disabled", "error", err)
	}

	// Create health checker
	healthChecker := http.NewHealthChecker(
		sessionStore,
		rateLimiter,
		auditService,
		"1.0.0", // TODO: inject from build flags later
	)

	transportOpts := []http.Option{
		http.WithAddr(cfg.Server.HTTPAddr),
		http.WithLogger(logger),
		http.WithHealthChecker(healthChecker),
	}

	// Add admin UI if available
	if adminHandler != nil {
		transportOpts = append(transportOpts, http.WithExtraHandler(adminHandler.Handler()))
		logger.Info("admin UI enabled", "path", "/admin")
	}

	transport := http.NewHTTPTransport(proxyService, transportOpts...)
	logger.Info("transport mode: HTTP", "addr", cfg.Server.HTTPAddr)
	return transport.Start(ctx)
}

// seedAuthFromConfig seeds identities and API keys from configuration into the auth store.
func seedAuthFromConfig(cfg *config.OSSConfig, authStore *memory.AuthStore) error {
	// Seed identities
	for _, identityCfg := range cfg.Auth.Identities {
		// Convert []string roles to []auth.Role
		roles := make([]auth.Role, len(identityCfg.Roles))
		for i, role := range identityCfg.Roles {
			roles[i] = auth.Role(role)
		}

		authStore.AddIdentity(&auth.Identity{
			ID:    identityCfg.ID,
			Name:  identityCfg.Name,
			Roles: roles,
		})
	}

	// Seed API keys
	for _, keyCfg := range cfg.Auth.APIKeys {
		// Strip "sha256:" prefix from hash
		// Config stores "sha256:abc123", AuthStore stores raw "abc123"
		hash := strings.TrimPrefix(keyCfg.KeyHash, "sha256:")

		authStore.AddKey(&auth.APIKey{
			Key:        hash,
			IdentityID: keyCfg.IdentityID,
			CreatedAt:  time.Now(),
		})
	}

	return nil
}

// seedPoliciesFromConfig seeds policies from configuration into the policy store.
func seedPoliciesFromConfig(cfg *config.OSSConfig, policyStore *memory.MemoryPolicyStore) error {
	now := time.Now()

	for _, policyCfg := range cfg.Policies {
		// Create rules from config
		rules := make([]policy.Rule, len(policyCfg.Rules))
		for i, ruleCfg := range policyCfg.Rules {
			rules[i] = policy.Rule{
				ID:        fmt.Sprintf("%s-rule-%d", policyCfg.Name, i),
				Name:      ruleCfg.Name,
				Condition: ruleCfg.Condition,
				Action:    policy.Action(ruleCfg.Action),
				ToolMatch: "*",     // Default to match all tools; condition handles filtering
				Priority:  100 - i, // Higher priority for earlier rules
			}
		}

		policyStore.AddPolicy(&policy.Policy{
			ID:        policyCfg.Name,
			Name:      policyCfg.Name,
			Enabled:   true,
			Rules:     rules,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	return nil
}

// createAuditStore creates an audit store based on configuration.
func createAuditStore(cfg *config.OSSConfig, logger *slog.Logger) (*memory.MemoryAuditStore, error) {
	switch {
	case cfg.Audit.Output == "stdout":
		logger.Debug("audit output: stdout")
		return memory.NewAuditStore(), nil

	case strings.HasPrefix(cfg.Audit.Output, "file://"):
		path := strings.TrimPrefix(cfg.Audit.Output, "file://")
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit file %s: %w", path, err)
		}
		logger.Debug("audit output: file", "path", path)
		return memory.NewAuditStoreWithWriter(f), nil

	default:
		return nil, fmt.Errorf("invalid audit output: %s (must be 'stdout' or 'file://path')", cfg.Audit.Output)
	}
}

// parseLogLevel converts a string log level to slog.Level.
// Returns slog.LevelInfo for unrecognized values.
func parseLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
