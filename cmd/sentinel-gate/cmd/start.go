// Package cmd provides the CLI commands for Sentinel Gate.
package cmd

import (
	"context"
	"fmt"
	"log/slog"
	stdhttp "net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/admin"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/http"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/httpgw"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/stdio"
	mcpclient "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/mcp"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/auth"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/ratelimit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/session"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
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

var devMode bool

func init() {
	startCmd.Flags().BoolVar(&devMode, "dev", false, "Enable development mode (verbose logging, relaxed validation)")
	rootCmd.AddCommand(startCmd)
}

func runStart(cmd *cobra.Command, args []string) error {
	// Load configuration (without validation, so CLI flags can override first)
	cfg, err := config.LoadConfigRaw()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override dev mode from CLI flag
	if devMode {
		cfg.DevMode = true
	}

	// Stdio transport is used ONLY when the user explicitly passes "-- command [args]".
	// This is decoupled from cfg.Upstream.Command to avoid Viper contamination issues.
	stdioTransport := len(args) > 0

	// Override upstream command from args if provided
	if len(args) > 0 {
		cfg.Upstream.Command = args[0]
		if len(args) > 1 {
			cfg.Upstream.Args = args[1:]
		} else {
			cfg.Upstream.Args = nil
		}
	}

	// Apply dev defaults (fills auth/policies if empty in dev mode)
	cfg.SetDevDefaults()

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

	// Create signal context for graceful shutdown.
	// stop() restores default signal handling so a second Ctrl+C does a hard kill.
	ctx, stop := signal.NotifyContext(context.Background(), gracefulSignals()...)
	go func() {
		<-ctx.Done()
		stop() // Restore default: next Ctrl+C = immediate exit.
	}()

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

	// Write PID file so "sentinel-gate stop" can find us.
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
// It implements the boot sequence: BOOT-01 through BOOT-09.
func run(ctx context.Context, cfg *config.OSSConfig, statePath string, stdioTransport bool, logger *slog.Logger) error {
	// Record start time for uptime calculation (used by admin API system info).
	startTime := time.Now().UTC()

	// ===== BOOT-01: DevMode check =====
	if err := proxy.LogDevModeWarning(logger, cfg.DevMode); err != nil {
		return err
	}

	// ===== BOOT-02: YAML config already loaded by runStart =====
	// YAML provides: server.http_addr, server.log_level, rate_limit, audit, auth, policies.

	// ===== BOOT-03: Load/create state.json =====
	stateStore := state.NewFileStateStore(statePath, logger)
	appState, err := stateStore.Load()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}
	// Save immediately to create the file if it didn't exist.
	if err := stateStore.Save(appState); err != nil {
		return fmt.Errorf("failed to save initial state: %w", err)
	}
	logger.Info("state loaded",
		"path", statePath,
		"upstreams", len(appState.Upstreams),
		"policies", len(appState.Policies),
		"default_policy", appState.DefaultPolicy,
	)

	// ===== BOOT-04: Populate in-memory stores =====
	authStore := memory.NewAuthStore()
	sessionStore := memory.NewSessionStore()
	sessionStore.StartCleanup(ctx)
	defer sessionStore.Stop()
	policyStore := memory.NewPolicyStore()
	upstreamStore := memory.NewUpstreamStore()
	var rateLimiter *memory.MemoryRateLimiter

	// Seed YAML identities/policies as READ-ONLY base (STAT-09).
	if err := seedAuthFromConfig(cfg, authStore); err != nil {
		return fmt.Errorf("failed to seed auth: %w", err)
	}
	logger.Debug("seeded auth from YAML config",
		"identities", len(cfg.Auth.Identities),
		"api_keys", len(cfg.Auth.APIKeys),
	)

	// Seed state.json identities and API keys into authStore.
	seedAuthFromState(appState, authStore, logger)

	if err := seedPoliciesFromConfig(cfg, policyStore); err != nil {
		return fmt.Errorf("failed to seed policies: %w", err)
	}
	logger.Debug("seeded policies from YAML config", "policies", len(cfg.Policies))

	// Backward compatibility: if YAML has a single upstream configured and state.json
	// has no upstreams, auto-create an upstream entry in state.json (migration path).
	if cfg.HasYAMLUpstream() && len(appState.Upstreams) == 0 {
		yamlUpstream := migrateYAMLUpstream(cfg)
		appState.Upstreams = append(appState.Upstreams, yamlUpstream)
		if err := stateStore.Save(appState); err != nil {
			return fmt.Errorf("failed to save migrated upstream: %w", err)
		}
		logger.Info("migrated YAML upstream to state.json",
			"name", yamlUpstream.Name,
			"type", yamlUpstream.Type,
		)
	}

	// Create upstream service and load state.json upstreams into memory.
	upstreamService := service.NewUpstreamService(upstreamStore, stateStore, logger)
	if err := upstreamService.LoadFromState(ctx, appState); err != nil {
		return fmt.Errorf("failed to load upstreams from state: %w", err)
	}

	// Parse session timeout from config
	sessionTimeout, err := time.ParseDuration(cfg.Server.SessionTimeout)
	if err != nil {
		sessionTimeout = 30 * time.Minute
		logger.Warn("invalid session_timeout, using default",
			"value", cfg.Server.SessionTimeout, "default", "30m")
	}

	// ===== Create services =====
	apiKeyService := auth.NewAPIKeyService(authStore)
	sessionService := session.NewSessionService(sessionStore, session.Config{
		Timeout: sessionTimeout,
	})
	policyService, err := service.NewPolicyService(ctx, policyStore, logger)
	if err != nil {
		return fmt.Errorf("failed to create policy service: %w", err)
	}

	// Create policy evaluation service for the API
	policyEvalService := service.NewPolicyEvaluationService(policyService, policyStore, stateStore, logger)

	// Create audit store
	auditStore, err := createAuditStore(cfg, logger)
	if err != nil {
		return fmt.Errorf("failed to create audit store: %w", err)
	}
	defer func() { _ = auditStore.Close() }()

	// Parse duration strings from audit config
	flushInterval, err := time.ParseDuration(cfg.Audit.FlushInterval)
	if err != nil {
		flushInterval = time.Second
		logger.Warn("invalid flush_interval, using default", "value", cfg.Audit.FlushInterval, "default", "1s")
	}

	sendTimeout, err := time.ParseDuration(cfg.Audit.SendTimeout)
	if err != nil {
		sendTimeout = 100 * time.Millisecond
		logger.Warn("invalid send_timeout, using default", "value", cfg.Audit.SendTimeout, "default", "100ms")
	}

	auditService := service.NewAuditService(auditStore, logger,
		service.WithChannelSize(cfg.Audit.ChannelSize),
		service.WithBatchSize(cfg.Audit.BatchSize),
		service.WithFlushInterval(flushInterval),
		service.WithSendTimeout(sendTimeout),
		service.WithWarningThreshold(cfg.Audit.WarningThreshold),
	)
	auditService.Start(ctx)
	defer auditService.Stop()

	// ===== BOOT-05: Start Upstream Manager =====
	clientFactory := defaultClientFactory(cfg)
	manager := service.NewUpstreamManager(upstreamService, clientFactory, logger)
	defer func() { _ = manager.Close() }()

	if err := manager.StartAll(ctx); err != nil {
		logger.Error("failed to start all upstreams", "error", err)
		// Non-fatal: some upstreams may fail, manager retries.
	}

	// Log connection results.
	statusAll := manager.StatusAll()
	var connectedCount int
	for _, status := range statusAll {
		if status == upstream.StatusConnected {
			connectedCount++
		}
	}
	logger.Info("upstream manager started",
		"total", len(statusAll),
		"connected", connectedCount,
	)

	// ===== BOOT-06: Run tool discovery =====
	toolCache := upstream.NewToolCache()
	discoveryService := service.NewToolDiscoveryService(upstreamService, toolCache, clientFactory, logger)
	defer discoveryService.Stop()

	if err := discoveryService.DiscoverAll(ctx); err != nil {
		logger.Error("tool discovery failed", "error", err)
		// Non-fatal: periodic retry will pick up tools later.
	}

	// Start periodic retry for upstreams with 0 tools.
	discoveryService.StartPeriodicRetry(ctx)

	toolCount := toolCache.Count()
	logger.Info("tool discovery complete", "tools", toolCount)

	// ===== Tool security: baseline + quarantine =====
	toolSecurityService := service.NewToolSecurityService(toolCache, stateStore, logger)
	toolSecurityService.LoadFromState(appState)

	// ===== Create Phase 2 admin services =====
	policyAdminService := service.NewPolicyAdminService(policyStore, stateStore, policyService, logger)

	// Load policies from state.json (policies created via admin API).
	// This runs after YAML seeding so that YAML policies are not duplicated.
	if err := policyAdminService.LoadPoliciesFromState(ctx, appState); err != nil {
		logger.Error("failed to load policies from state", "error", err)
		// Non-fatal: YAML policies still work, state policies are lost.
	}

	identityService := service.NewIdentityService(stateStore, logger)
	if err := identityService.Init(); err != nil {
		return fmt.Errorf("init identity service: %w", err)
	}
	statsService := service.NewStatsService()

	// Create agent registry for tracking running agent processes.
	agentRegistry := service.NewAgentRegistry()

	// Create AdminAPIHandler with all dependencies.
	apiHandler := admin.NewAdminAPIHandler(
		admin.WithUpstreamService(upstreamService),
		admin.WithUpstreamManager(manager),
		admin.WithDiscoveryService(discoveryService),
		admin.WithToolCache(toolCache),
		admin.WithPolicyService(policyService),
		admin.WithPolicyStore(policyStore),
		admin.WithPolicyEvalService(policyEvalService),
		admin.WithPolicyAdminService(policyAdminService),
		admin.WithIdentityService(identityService),
		admin.WithAuditService(auditService),
		admin.WithAuditReader(auditStore),
		admin.WithStatsService(statsService),
		admin.WithStateStore(stateStore),
		admin.WithAuthStore(authStore),
		admin.WithToolSecurityService(toolSecurityService),
		admin.WithAgentRegistry(agentRegistry),

		admin.WithAPILogger(logger),
		admin.WithBuildInfo(&admin.BuildInfo{
			Version:   Version,
			Commit:    Commit,
			BuildDate: BuildDate,
		}),
		admin.WithStartTime(startTime),
	)

	// ===== BOOT-07: Build interceptor chain =====
	// Chain order (inner to outer): UpstreamRouter -> policy -> audit -> userRateLimit (optional) -> auth -> ipRateLimit (optional) -> validation
	//
	// PolicyInterceptor is natively migrated to ActionInterceptor (CANON-10).
	// It operates directly on CanonicalAction. Other interceptors (auth, audit,
	// validation, rateLimit) remain as legacy MessageInterceptors wrapped via LegacyAdapter.
	cacheAdapter := proxy.NewToolCacheAdapter(toolCache)
	router := proxy.NewUpstreamRouter(cacheAdapter, manager, logger)

	// Native policy chain: PolicyActionInterceptor -> OutboundInterceptor -> ResponseScanInterceptor -> LegacyAdapter(router)
	// The router stays as a legacy MessageInterceptor; policy is native.
	// Outbound control sits between policy and response scanning, checking
	// destination URLs before execution. Response scanning sits before the
	// upstream router, scanning tool results for prompt injection after return.
	policyNormalizer := action.NewMCPNormalizer()
	routerAdapter := action.NewLegacyAdapter(router, "upstream-router")

	// Content scanning config (default: monitor mode, enabled)
	scanMode := action.ScanModeMonitor
	scanEnabled := true
	if appState.ContentScanningConfig != nil {
		scanMode = action.ScanMode(appState.ContentScanningConfig.Mode)
		scanEnabled = appState.ContentScanningConfig.Enabled
	}
	responseScanner := action.NewResponseScanner()
	responseScanInterceptor := action.NewResponseScanInterceptor(
		responseScanner, routerAdapter, scanMode, scanEnabled, logger,
	)
	logger.Info("response scanning configured", "mode", scanMode, "enabled", scanEnabled)

	// Wire the response scan interceptor into the admin API handler.
	// This happens after BOOT-07 creates the interceptor, but the admin handler
	// was already created above. SetResponseScanController bridges the ordering gap.
	apiHandler.SetResponseScanController(responseScanInterceptor)

	// Outbound control: URL extraction + DNS pinning + persisted rules
	dnsResolver := action.NewDNSResolver(logger)
	// Start with empty rules; OutboundAdminService.LoadFromState will populate them.
	outboundInterceptor := action.NewOutboundInterceptor(nil, dnsResolver, responseScanInterceptor, logger)

	// Create outbound rule store and admin service.
	outboundStore := action.NewMemoryOutboundStore()
	outboundAdminService := service.NewOutboundAdminService(outboundStore, stateStore, logger, outboundInterceptor)

	// Load persisted outbound rules from state.json (or default blocklist on fresh install).
	if err := outboundAdminService.LoadFromState(ctx, appState); err != nil {
		logger.Error("failed to load outbound rules from state", "error", err)
		// Non-fatal: default blocklist still loaded at interceptor construction.
	}
	outboundRuleCount, _ := outboundStore.List(ctx)
	logger.Info("outbound control configured", "rules", len(outboundRuleCount))

	// Wire the outbound admin service into the admin API handler.
	// This happens after BOOT-07 creates the service, but the admin handler
	// was already created above. SetOutboundAdminService bridges the ordering gap.
	apiHandler.SetOutboundAdminService(outboundAdminService)

	// Create approval store and interceptor (HITL blocking)
	approvalStore := action.NewApprovalStore(100)
	approvalInterceptor := action.NewApprovalInterceptor(approvalStore, outboundInterceptor, logger)

	// Wire the approval store into the admin API handler for HITL approval management.
	apiHandler.SetApprovalStore(approvalStore)

	nativePolicyInterceptor := action.NewPolicyActionInterceptor(policyService, approvalInterceptor, logger)
	// Quarantine interceptor: blocks quarantined tools before policy evaluation.
	quarantineInterceptor := action.NewQuarantineInterceptor(toolSecurityService, nativePolicyInterceptor, logger)
	// Bridge back to proxy.MessageInterceptor so audit can use it as its next
	policyBridge := action.NewInterceptorChain(policyNormalizer, quarantineInterceptor, logger)

	// Build post-auth chain: Audit -> UserRateLimit (optional) -> Policy -> ...
	// Audit wraps UserRateLimit so rate-limited requests are still recorded in the audit log.
	// UserRateLimit sits after auth so msg.Session is populated for per-user rate limiting.

	// Declare rate limit configs at outer scope so ipConfig is accessible after the if block.
	var ipConfig, userConfig ratelimit.RateLimitConfig

	// Build pre-audit chain: UserRateLimit (optional) -> Policy
	var preAuditChain proxy.MessageInterceptor = policyBridge

	if cfg.RateLimit.Enabled {
		cleanupInterval, err := time.ParseDuration(cfg.RateLimit.CleanupInterval)
		if err != nil {
			cleanupInterval = 5 * time.Minute
			logger.Warn("invalid rate_limit.cleanup_interval, using default",
				"value", cfg.RateLimit.CleanupInterval, "default", "5m")
		}

		maxTTL, err := time.ParseDuration(cfg.RateLimit.MaxTTL)
		if err != nil {
			maxTTL = 1 * time.Hour
			logger.Warn("invalid rate_limit.max_ttl, using default",
				"value", cfg.RateLimit.MaxTTL, "default", "1h")
		}

		rateLimiter = memory.NewRateLimiterWithConfig(cleanupInterval, maxTTL)

		ipConfig = ratelimit.RateLimitConfig{
			Rate:   cfg.RateLimit.IPRate,
			Burst:  cfg.RateLimit.IPRate,
			Period: time.Minute,
		}
		userConfig = ratelimit.RateLimitConfig{
			Rate:   cfg.RateLimit.UserRate,
			Burst:  cfg.RateLimit.UserRate,
			Period: time.Minute,
		}

		// User rate limit: between audit and policy (has session, audit captures rate-limit denials)
		userRateLimiter := proxy.NewUserRateLimitInterceptor(rateLimiter, userConfig, policyBridge, logger)
		preAuditChain = userRateLimiter

		logger.Debug("rate limiting enabled",
			"ip_rate", cfg.RateLimit.IPRate,
			"user_rate", cfg.RateLimit.UserRate,
			"cleanup_interval", cleanupInterval,
			"max_ttl", maxTTL,
		)
	} else {
		rateLimiter = memory.NewRateLimiter()
	}

	auditInterceptor := proxy.NewAuditInterceptor(auditService, statsService, preAuditChain, logger)
	var postAuthChain proxy.MessageInterceptor = auditInterceptor

	authInterceptor := proxy.NewAuthInterceptor(apiKeyService, sessionService, postAuthChain, logger, cfg.DevMode)
	authInterceptor.StartCleanup(ctx)
	defer authInterceptor.Stop()

	var chainHead proxy.MessageInterceptor = authInterceptor

	// IP rate limit: before auth (prevents brute force)
	if cfg.RateLimit.Enabled {
		chainHead = proxy.NewIPRateLimitInterceptor(rateLimiter, ipConfig, authInterceptor, logger)
	}

	rateLimiter.StartCleanup(ctx)
	defer rateLimiter.Stop()

	// Validation interceptor is always outermost.
	validationInterceptor := proxy.NewValidationInterceptor(chainHead, logger)

	// Wrap the entire legacy chain in CanonicalAction InterceptorChain.
	// The InterceptorChain implements proxy.MessageInterceptor, so it's a
	// drop-in replacement. Flow: mcp.Message -> Normalize -> LegacyAdapter
	// (which extracts mcp.Message and runs the full legacy chain) -> extract result.
	mcpNormalizer := action.NewMCPNormalizer()
	canonicalChain := action.NewLegacyAdapter(validationInterceptor, "validation-chain")
	interceptorChain := action.NewInterceptorChain(mcpNormalizer, canonicalChain, logger)

	// ===== HTTP Gateway (optional) =====
	var httpGatewayHandler stdhttp.Handler
	if cfg.HTTPGateway.Enabled {
		// Build an independent ActionInterceptor chain for HTTP Gateway requests.
		// This reuses the same services (policyService, responseScanner, dnsResolver)
		// but creates separate interceptor instances so "next" pointers differ:
		// HTTP chain terminates with a passthrough (handler does the forwarding),
		// while MCP chain terminates with the upstream router.
		httpGWPassthrough := action.ActionInterceptorFunc(func(ctx context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
			return a, nil // Allow -- the handler will forward the request
		})
		httpGWResponseScan := action.NewResponseScanInterceptor(
			responseScanner, httpGWPassthrough, scanMode, scanEnabled, logger,
		)
		// Sync content scanning config changes from admin API to the HTTP gateway's
		// response scan interceptor (separate instance from the MCP chain's one).
		apiHandler.AddResponseScanController(httpGWResponseScan)
		httpGWOutbound := action.NewOutboundInterceptor(nil, dnsResolver, httpGWResponseScan, logger)
		// Register this interceptor for dynamic rule reload via admin API CRUD operations.
		outboundAdminService.AddInterceptor(httpGWOutbound)
		// Reload to populate the newly added interceptor with current rules.
		outboundAdminService.ReloadRules(ctx)
		httpGWApproval := action.NewApprovalInterceptor(approvalStore, httpGWOutbound, logger)
		httpGWPolicy := action.NewPolicyActionInterceptor(policyService, httpGWApproval, logger)
		httpGWQuarantine := action.NewQuarantineInterceptor(toolSecurityService, httpGWPolicy, logger)

		gwHandler := httpgw.NewHandler(httpGWQuarantine, logger)

		// Parse timeout from config
		gwTimeout, parseErr := time.ParseDuration(cfg.HTTPGateway.Timeout)
		if parseErr != nil {
			gwTimeout = 30 * time.Second
		}
		gwHandler.SetTimeout(gwTimeout)

		// Reverse proxy targets
		rp := httpgw.NewReverseProxy(logger)
		rp.SetTimeout(gwTimeout)

		// Load targets from YAML config
		var rpTargets []httpgw.UpstreamTarget
		for i, t := range cfg.HTTPGateway.Targets {
			rpTargets = append(rpTargets, httpgw.UpstreamTarget{
				ID:          fmt.Sprintf("yaml-target-%d", i),
				Name:        t.Name,
				PathPrefix:  t.PathPrefix,
				Upstream:    t.Upstream,
				StripPrefix: t.StripPrefix,
				Headers:     t.Headers,
				Enabled:     true,
			})
		}

		// Load targets from state.json (admin-created)
		for _, t := range appState.HTTPGatewayTargets {
			if t.Enabled {
				rpTargets = append(rpTargets, httpgw.UpstreamTarget{
					ID:          t.ID,
					Name:        t.Name,
					PathPrefix:  t.PathPrefix,
					Upstream:    t.Upstream,
					StripPrefix: t.StripPrefix,
					Headers:     t.Headers,
					Enabled:     true,
				})
			}
		}

		if len(rpTargets) > 0 {
			rp.SetTargets(rpTargets)
			logger.Info("http gateway reverse proxy configured", "targets", len(rpTargets))
		}
		// Always attach the ReverseProxy so targets added via admin API at
		// runtime are visible to the handler (even when no targets at boot).
		gwHandler.SetReverseProxy(rp)

		// Wire WebSocket proxy for the HTTP gateway
		wsProxy := httpgw.NewWebSocketProxy(
			responseScanner,
			func() action.ScanMode { return httpGWResponseScan.Mode() },
			func() bool { return httpGWResponseScan.Enabled() },
			logger,
		)
		gwHandler.SetWebSocketProxy(wsProxy)

		// Wire response scanner for HTTP gateway handler and reverse proxy
		gwHandler.SetResponseScanner(
			responseScanner,
			func() action.ScanMode { return httpGWResponseScan.Mode() },
			func() bool { return httpGWResponseScan.Enabled() },
		)
		rp.SetResponseScanner(
			responseScanner,
			func() action.ScanMode { return httpGWResponseScan.Mode() },
			func() bool { return httpGWResponseScan.Enabled() },
		)

		// Auth middleware
		gwAuth := httpgw.NewAuthMiddleware(httpgw.AuthConfig{
			APIKeyService: apiKeyService,
			DevMode:       cfg.DevMode,
			Logger:        logger,
		})

		// TLS Inspection: when enabled, TLSInspector wraps the auth+handler combo.
		// Non-CONNECT requests pass through to auth+handler directly.
		// CONNECT requests are either tunneled (bypassed) or intercepted (MITM).
		var caManager *httpgw.CAManager // hoisted so admin controller can access it
		if cfg.HTTPGateway.TLSInspection.Enabled {
			// Resolve CA directory
			caDir := cfg.HTTPGateway.TLSInspection.CADir
			if strings.HasPrefix(caDir, "~") {
				if home, err := os.UserHomeDir(); err == nil {
					caDir = filepath.Join(home, caDir[1:])
				}
			}

			// Parse cert TTL
			certTTL, parseErr := time.ParseDuration(cfg.HTTPGateway.TLSInspection.CertTTL)
			if parseErr != nil {
				certTTL = time.Hour
				logger.Warn("invalid tls_inspection.cert_ttl, using default",
					"value", cfg.HTTPGateway.TLSInspection.CertTTL, "default", "1h")
			}

			// Create CA manager
			var caErr error
			caManager, caErr = httpgw.NewCAManager(httpgw.CAConfig{
				CertFile: filepath.Join(caDir, "ca-cert.pem"),
				KeyFile:  filepath.Join(caDir, "ca-key.pem"),
			}, logger)
			if caErr != nil {
				return fmt.Errorf("failed to create CA manager for TLS inspection: %w", caErr)
			}

			// Create cert cache
			certCache := httpgw.NewCertCache(caManager, certTTL, logger)

			// Merge bypass list from YAML and state.json
			bypassList := make([]string, len(cfg.HTTPGateway.TLSInspection.BypassList))
			copy(bypassList, cfg.HTTPGateway.TLSInspection.BypassList)

			tlsEnabled := cfg.HTTPGateway.TLSInspection.Enabled
			if appState.TLSInspectionConfig != nil {
				tlsEnabled = appState.TLSInspectionConfig.Enabled
				// Merge bypass lists (union, deduplicate)
				seen := make(map[string]bool, len(bypassList))
				for _, d := range bypassList {
					seen[d] = true
				}
				for _, d := range appState.TLSInspectionConfig.BypassList {
					if !seen[d] {
						bypassList = append(bypassList, d)
						seen[d] = true
					}
				}
			}

			// Create TLS inspector wrapping auth+handler
			tlsInspector := httpgw.NewTLSInspector(httpgw.TLSInspectorConfig{
				Enabled:    tlsEnabled,
				BypassList: bypassList,
				CertCache:  certCache,
				Handler:    gwAuth(gwHandler),
				Logger:     logger,
			})

			httpGatewayHandler = tlsInspector
			logger.Info("tls inspection enabled",
				"ca_dir", caDir,
				"bypass_domains", len(bypassList),
				"cert_ttl", certTTL,
			)
		} else {
			// Even without TLS inspection, we need the TLSInspector to handle
			// CONNECT requests (used by HTTP_PROXY for HTTPS destinations).
			// With Enabled=false it just creates raw TCP tunnels.
			tlsInspector := httpgw.NewTLSInspector(httpgw.TLSInspectorConfig{
				Enabled: false,
				Handler: gwAuth(gwHandler),
				Logger:  logger,
			})
			httpGatewayHandler = tlsInspector
			logger.Info("tls inspection disabled")
		}

		// Wire HTTP Gateway admin controller for live config management.
		// The controller exposes TLS, bypass list, targets, and CA cert to the admin API.
		gwCtrl := &httpGatewayControllerImpl{
			reverseProxy: rp,
		}
		// Always wire the TLS inspector so the admin API can toggle TLS and manage bypass list.
		// The TLSInspector is created in both branches (enabled and disabled).
		if ti, ok := httpGatewayHandler.(*httpgw.TLSInspector); ok {
			gwCtrl.tlsInspector = ti
		}
		if cfg.HTTPGateway.TLSInspection.Enabled {
			gwCtrl.caManager = caManager
		}
		apiHandler.SetHTTPGatewayController(gwCtrl)

		logger.Info("http gateway enabled (single-port mode)")
	}

	// ===== BOOT-08: Create proxy service and start transport =====
	// In multi-upstream mode (state.json has upstreams), the UpstreamRouter handles
	// routing to multiple upstreams — no YAML-based single client needed.
	//
	// YAML single-upstream client is only created when:
	// - YAML has upstream config (HTTP or Command), AND
	// - State has no upstreams (not in multi-upstream mode)
	var mcpClient outbound.MCPClient
	hasStateUpstreams := len(appState.Upstreams) > 0
	if cfg.HasYAMLUpstream() && !hasStateUpstreams {
		httpTimeout, err := time.ParseDuration(cfg.Upstream.HTTPTimeout)
		if err != nil {
			httpTimeout = 30 * time.Second
			logger.Warn("invalid http_timeout, using default",
				"value", cfg.Upstream.HTTPTimeout, "default", "30s")
		}

		if cfg.Upstream.HTTP != "" {
			mcpClient = mcpclient.NewHTTPClient(cfg.Upstream.HTTP,
				mcpclient.WithTimeout(httpTimeout))
			logger.Info("upstream mode: HTTP", "endpoint", cfg.Upstream.HTTP, "timeout", httpTimeout)
		} else {
			mcpClient = mcpclient.NewStdioClient(cfg.Upstream.Command, cfg.Upstream.Args...)
			logger.Info("upstream mode: stdio", "command", cfg.Upstream.Command, "args", cfg.Upstream.Args)
		}
	}

	proxyService := service.NewProxyService(mcpClient, interceptorChain, logger)

	// ===== BOOT-09: Print startup banner =====
	// Count rules from all loaded policies (YAML + state.json).
	ruleCount := countRules(ctx, policyStore)

	logger.Info("sentinel-gate starting",
		"version", Version,
		"dev_mode", cfg.DevMode,
		"http_addr", cfg.Server.HTTPAddr,
		"upstreams", len(statusAll),
		"connected", connectedCount,
		"tools", toolCount,
		"rules", ruleCount,
		"rate_limit", cfg.RateLimit.Enabled,
		"audit_output", cfg.Audit.Output,
		"state_file", statePath,
	)

	// ===== Start transport =====
	// Stdio transport is only used when explicitly requested via "-- command" CLI args.
	// This avoids false positives from Viper config contamination.
	if stdioTransport {
		transport := stdio.NewStdioTransport(proxyService)
		logger.Info("transport mode: stdio")
		return transport.Start(ctx)
	}

	// Print startup banner to stderr (only in HTTP mode, not stdio).
	printBanner(Version, cfg.Server.HTTPAddr, cfg.DevMode, len(statusAll), connectedCount, toolCount, ruleCount)

	// HTTP transport mode.
	adminHandler, err := admin.NewAdminHandler(cfg, logger)
	if err != nil {
		logger.Warn("failed to create admin handler, UI disabled", "error", err)
	}

	healthChecker := http.NewHealthChecker(
		sessionStore,
		rateLimiter,
		auditService,
		Version,
	)

	transportOpts := []http.Option{
		http.WithAddr(cfg.Server.HTTPAddr),
		http.WithLogger(logger),
		http.WithHealthChecker(healthChecker),
	}

	// Build composite admin handler: new JSON API + legacy UI.
	// The API handler's Routes() returns a mux that handles /admin/api/* routes.
	// The legacy admin handler serves /admin/ (HTML UI).
	// A composite mux tries the API handler first, then falls back to the legacy handler.
	compositeMux := stdhttp.NewServeMux()
	compositeMux.Handle("/admin/api/", apiHandler.Routes())
	if adminHandler != nil {
		compositeMux.Handle("/admin/", adminHandler.Handler())
		compositeMux.Handle("/admin", adminHandler.Handler())
	}
	transportOpts = append(transportOpts, http.WithExtraHandler(compositeMux))

	// Pass HTTP Gateway handler to transport for single-port routing.
	// The transport mux routes /mcp -> MCP handler, everything else -> gateway handler.
	// Note: cfg.HTTPGateway.PathPrefix is preserved for backward compatibility but
	// no longer used for routing -- single-port mode is always active when gateway is enabled.
	if httpGatewayHandler != nil {
		transportOpts = append(transportOpts, http.WithHTTPGatewayHandler(httpGatewayHandler))
	}
	logger.Info("admin enabled", "api", "/admin/api/", "ui", "/admin/")

	transport := http.NewHTTPTransport(proxyService, transportOpts...)
	logger.Info("transport mode: HTTP", "addr", cfg.Server.HTTPAddr)
	return transport.Start(ctx)
}

// defaultClientFactory returns a ClientFactory that creates MCPClient instances
// based on the upstream type. It uses the YAML config for HTTP timeout settings.
func defaultClientFactory(cfg *config.OSSConfig) service.ClientFactory {
	return func(u *upstream.Upstream) (outbound.MCPClient, error) {
		switch u.Type {
		case upstream.UpstreamTypeStdio:
			return mcpclient.NewStdioClient(u.Command, u.Args...), nil
		case upstream.UpstreamTypeHTTP:
			httpTimeout, err := time.ParseDuration(cfg.Upstream.HTTPTimeout)
			if err != nil {
				httpTimeout = 30 * time.Second
			}
			return mcpclient.NewHTTPClient(u.URL, mcpclient.WithTimeout(httpTimeout)), nil
		default:
			return nil, fmt.Errorf("unsupported upstream type: %s", u.Type)
		}
	}
}

// migrateYAMLUpstream creates a state.json UpstreamEntry from the YAML config's
// single upstream. This provides backward compatibility for existing users.
func migrateYAMLUpstream(cfg *config.OSSConfig) state.UpstreamEntry {
	now := time.Now().UTC()
	entry := state.UpstreamEntry{
		ID:        uuid.New().String(),
		Name:      "default",
		Enabled:   true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if cfg.Upstream.HTTP != "" {
		entry.Type = string(upstream.UpstreamTypeHTTP)
		entry.URL = cfg.Upstream.HTTP
	} else {
		entry.Type = string(upstream.UpstreamTypeStdio)
		entry.Command = cfg.Upstream.Command
		entry.Args = cfg.Upstream.Args
	}

	return entry
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

// seedAuthFromState loads identities and API keys from state.json into the auth store.
// This is needed because keys created via the admin UI are stored in state.json
// but the auth interceptor validates against the in-memory auth store.
func seedAuthFromState(appState *state.AppState, authStore *memory.AuthStore, logger *slog.Logger) {
	// Load identities from state
	for _, identity := range appState.Identities {
		roles := make([]auth.Role, len(identity.Roles))
		for i, role := range identity.Roles {
			roles[i] = auth.Role(role)
		}
		authStore.AddIdentity(&auth.Identity{
			ID:    identity.ID,
			Name:  identity.Name,
			Roles: roles,
		})
	}

	// Load API keys from state (stored with Argon2id hashes)
	for _, key := range appState.APIKeys {
		if key.Revoked {
			continue
		}
		authStore.AddKey(&auth.APIKey{
			Key:        key.KeyHash, // Argon2id hash - verified by iteration in Validate()
			IdentityID: key.IdentityID,
			Name:       key.Name,
			CreatedAt:  key.CreatedAt,
			Revoked:    key.Revoked,
		})
	}

	logger.Debug("seeded auth from state.json",
		"identities", len(appState.Identities),
		"api_keys", len(appState.APIKeys),
	)
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
		logger.Debug("audit output: stdout", "buffer_size", cfg.Audit.BufferSize)
		return memory.NewAuditStore(cfg.Audit.BufferSize), nil

	case strings.HasPrefix(cfg.Audit.Output, "file://"):
		path := parseFileURI(cfg.Audit.Output)
		if path == "" {
			return nil, fmt.Errorf("invalid audit file URI: %s", cfg.Audit.Output)
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit file %s: %w", path, err)
		}
		logger.Debug("audit output: file", "path", path, "buffer_size", cfg.Audit.BufferSize)
		return memory.NewAuditStoreWithWriter(f, cfg.Audit.BufferSize), nil

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

// countRules returns the total number of rules across all enabled policies.
func countRules(ctx context.Context, policyStore *memory.MemoryPolicyStore) int {
	policies, err := policyStore.GetAllPolicies(ctx)
	if err != nil {
		return 0
	}
	count := 0
	for _, p := range policies {
		count += len(p.Rules)
	}
	return count
}

// printBanner prints a formatted startup banner to stderr with version, addresses,
// mode, and resource counts. Only called in HTTP mode to avoid interfering with
// stdio MCP transport on stdout.
func printBanner(version, httpAddr string, devMode bool, upstreamCount, connectedCount, toolCount, ruleCount int) {
	const (
		reset  = "\033[0m"
		bold   = "\033[1m"
		cyan   = "\033[36m"
		green  = "\033[32m"
		yellow = "\033[33m"
		dim    = "\033[2m"
	)

	adminURL := fmt.Sprintf("http://localhost%s/admin", httpAddr)
	if !strings.HasPrefix(httpAddr, ":") {
		adminURL = fmt.Sprintf("http://%s/admin", httpAddr)
	}

	proxyURL := fmt.Sprintf("http://localhost%s/mcp", httpAddr)
	if !strings.HasPrefix(httpAddr, ":") {
		proxyURL = fmt.Sprintf("http://%s/mcp", httpAddr)
	}

	modeStr := green + "production" + reset
	if devMode {
		modeStr = yellow + "development" + reset + dim + " (no auth)" + reset
	}

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  %s%s SentinelGate %s%s\n", bold, cyan, version, reset)
	fmt.Fprintf(os.Stderr, "  %s─────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Admin UI:", adminURL)
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Proxy:", proxyURL)
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Mode:", modeStr)
	fmt.Fprintf(os.Stderr, "  %-14s %d connected / %d configured\n", "Upstreams:", connectedCount, upstreamCount)
	fmt.Fprintf(os.Stderr, "  %-14s %d discovered\n", "Tools:", toolCount)
	fmt.Fprintf(os.Stderr, "  %-14s %d active\n", "Rules:", ruleCount)
	fmt.Fprintf(os.Stderr, "  %s─────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "\n")
}

// httpGatewayControllerImpl implements admin.HTTPGatewayController by wrapping
// the TLSInspector, ReverseProxy, and CAManager from the HTTP Gateway.
type httpGatewayControllerImpl struct {
	tlsInspector *httpgw.TLSInspector // may be nil if TLS inspection disabled
	reverseProxy *httpgw.ReverseProxy
	caManager    *httpgw.CAManager // may be nil if TLS inspection disabled
}

func (c *httpGatewayControllerImpl) TLSEnabled() bool {
	if c.tlsInspector == nil {
		return false
	}
	return c.tlsInspector.IsEnabled()
}

func (c *httpGatewayControllerImpl) SetTLSEnabled(enabled bool) {
	if c.tlsInspector != nil {
		c.tlsInspector.SetEnabled(enabled)
	}
}

func (c *httpGatewayControllerImpl) BypassList() []string {
	if c.tlsInspector == nil {
		return nil
	}
	return c.tlsInspector.BypassList()
}

func (c *httpGatewayControllerImpl) SetBypassList(list []string) {
	if c.tlsInspector != nil {
		c.tlsInspector.SetBypassList(list)
	}
}

func (c *httpGatewayControllerImpl) Targets() []httpgw.UpstreamTarget {
	if c.reverseProxy == nil {
		return nil
	}
	return c.reverseProxy.Targets()
}

func (c *httpGatewayControllerImpl) SetTargets(targets []httpgw.UpstreamTarget) {
	if c.reverseProxy != nil {
		c.reverseProxy.SetTargets(targets)
	}
}

func (c *httpGatewayControllerImpl) CACertPEM() []byte {
	if c.caManager == nil {
		return nil
	}
	return c.caManager.CACertPEM()
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
	return os.WriteFile(path, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
}
