package cmd

import (
	"context"
	stdhttp "net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/admin"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/http"
	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/stdio"
	mcpclient "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/mcp"
	"github.com/Sentinel-Gate/Sentinelgate/internal/lifecycle"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// bootTransport creates the proxy service and MCP client (BOOT-08).
func (bc *bootContext) bootTransport() {
	var mcpClient = bc.mcpClient
	hasStateUpstreams := len(bc.appState.Upstreams) > 0

	if bc.cfg.HasYAMLUpstream() && !hasStateUpstreams {
		httpTimeout, err := time.ParseDuration(bc.cfg.Upstream.HTTPTimeout)
		if err != nil {
			httpTimeout = 30 * time.Second
			bc.logger.Warn("invalid http_timeout, using default",
				"value", bc.cfg.Upstream.HTTPTimeout, "default", "30s")
		}
		if bc.cfg.Upstream.HTTP != "" {
			mcpClient = mcpclient.NewHTTPClient(bc.cfg.Upstream.HTTP,
				mcpclient.WithTimeout(httpTimeout))
			bc.logger.Info("upstream mode: HTTP", "endpoint", bc.cfg.Upstream.HTTP, "timeout", httpTimeout)
		} else {
			mcpClient = mcpclient.NewStdioClient(bc.cfg.Upstream.Command, bc.cfg.Upstream.Args...)
			bc.logger.Info("upstream mode: stdio", "command", bc.cfg.Upstream.Command, "args", bc.cfg.Upstream.Args)
		}
	}

	bc.proxyService = service.NewProxyService(mcpClient, bc.interceptorChain, bc.logger)
}

// startTransport prints banner and starts the appropriate transport (BOOT-09).
func (bc *bootContext) startTransport(ctx context.Context, stdioTransport bool) error {
	// Count rules for banner
	ruleCount := countRules(ctx, bc.policyStore)

	bc.logger.Info("sentinel-gate starting",
		"version", Version,
		"http_addr", bc.cfg.Server.HTTPAddr,
		"upstreams", len(bc.statusAll),
		"connected", bc.connectedCount,
		"tools", bc.toolCount,
		"rules", ruleCount,
		"rate_limit", bc.cfg.RateLimit.Enabled,
		"audit_output", bc.cfg.Audit.Output,
		"state_file", bc.statePath,
	)

	// Stdio transport
	// M-30: Stdio mode does not have a PhaseStopAccepting hook for graceful stdin
	// shutdown. Stdin is closed by the parent process; no explicit draining is needed.
	if stdioTransport {
		transport := stdio.NewStdioTransport(bc.proxyService)

		// Tool change notifier for stdio clients
		toolChangeNotifier := stdio.NewStdioToolChangeNotifier(transport)
		bc.discoveryService.SetNotifier(toolChangeNotifier)
		bc.apiHandler.SetToolChangeNotifier(toolChangeNotifier)

		bc.logger.Info("transport mode: stdio")
		return transport.Start(ctx)
	}

	// Print banner (HTTP mode only)
	printBanner(Version, bc.cfg.Server.HTTPAddr,
		len(bc.statusAll), bc.connectedCount, bc.toolCount, ruleCount)

	// Admin handler
	adminHandler, err := admin.NewAdminHandler(bc.cfg, bc.logger)
	if err != nil {
		bc.logger.Warn("failed to create admin handler, UI disabled", "error", err)
	}

	healthChecker := http.NewHealthChecker(bc.sessionStore, bc.rateLimiter, bc.auditService, Version)

	transportOpts := []http.Option{
		http.WithAddr(bc.cfg.Server.HTTPAddr),
		http.WithLogger(bc.logger),
		http.WithHealthChecker(healthChecker),
	}

	// Composite admin mux
	compositeMux := stdhttp.NewServeMux()
	compositeMux.Handle("/admin/api/", bc.apiHandler.Routes())
	if adminHandler != nil {
		compositeMux.Handle("/admin/", adminHandler.Handler())
		compositeMux.Handle("/admin", adminHandler.Handler())
	}
	transportOpts = append(transportOpts, http.WithExtraHandler(compositeMux))

	// Clean up per-session framework tracking when sessions are terminated.
	if bc.upstreamRouter != nil {
		transportOpts = append(transportOpts, http.WithSessionTerminateCallback(bc.upstreamRouter.CleanupSession))
	}

	bc.logger.Info("admin enabled", "api", "/admin/api/", "ui", "/admin/")

	transport := http.NewHTTPTransport(bc.proxyService, transportOpts...)

	// Register HTTP server shutdown in lifecycle (PhaseStopAccepting)
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "http-shutdown", Phase: lifecycle.PhaseStopAccepting,
		Timeout: 10 * time.Second,
		Fn:      transport.Shutdown,
	})

	// Tool change notifier
	toolChangeNotifier := http.NewHTTPToolChangeNotifier(transport)
	bc.discoveryService.SetNotifier(toolChangeNotifier)
	bc.apiHandler.SetToolChangeNotifier(toolChangeNotifier)

	// Notification forwarder: route upstream notifications to SSE clients (H-4).
	if bc.upstreamRouter != nil {
		notifForwarder := http.NewHTTPNotificationForwarder(transport)
		bc.upstreamRouter.SetNotificationForwarder(notifForwarder)
	}

	bc.logger.Info("transport mode: HTTP", "addr", bc.cfg.Server.HTTPAddr)
	return transport.Start(ctx)
}
