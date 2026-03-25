package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	mcpclient "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/mcp"
	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
	"github.com/Sentinel-Gate/Sentinelgate/internal/lifecycle"
	"github.com/Sentinel-Gate/Sentinelgate/internal/port/outbound"
	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// bootUpstreams starts the upstream manager, runs tool discovery, and
// sets up tool security (BOOT-05 + BOOT-06).
func (bc *bootContext) bootUpstreams(ctx context.Context) error {
	// BOOT-05: Start Upstream Manager
	clientFactory := defaultClientFactory(bc.cfg)
	bc.upstreamManager = service.NewUpstreamManager(bc.upstreamService, clientFactory, bc.logger)
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "upstream-close", Phase: lifecycle.PhaseCloseConnections,
		Timeout: 10 * time.Second,
		Fn:      func(ctx context.Context) error { return bc.upstreamManager.Close() },
	})

	if err := bc.upstreamManager.StartAll(ctx); err != nil {
		bc.logger.Error("failed to start all upstreams", "error", err)
	}

	bc.statusAll = bc.upstreamManager.StatusAll()
	for _, status := range bc.statusAll {
		if status == upstream.StatusConnected {
			bc.connectedCount++
		}
	}
	bc.logger.Info("upstream manager started",
		"total", len(bc.statusAll),
		"connected", bc.connectedCount,
	)

	// BOOT-06: Run tool discovery
	bc.toolCache = upstream.NewToolCache()
	bc.discoveryService = service.NewToolDiscoveryService(bc.upstreamService, bc.toolCache, clientFactory, bc.logger)
	bc.lifecycle.Register(lifecycle.Hook{
		Name: "discovery-service-stop", Phase: lifecycle.PhaseDrainRequests,
		Timeout: 5 * time.Second,
		Fn:      func(ctx context.Context) error { bc.discoveryService.Stop(); return nil },
	})

	// Tool security: baseline + quarantine + integrity checks (Upgrade 4).
	// Created before first DiscoverAll so integrity check runs on first discovery.
	bc.toolSecurityService = service.NewToolSecurityService(bc.toolCache, bc.stateStore, bc.logger)
	bc.toolSecurityService.LoadFromState(bc.appState)
	if bc.eventBus != nil {
		bc.toolSecurityService.SetEventBus(bc.eventBus)
	}
	bc.discoveryService.SetToolSecurityService(bc.toolSecurityService)

	if err := bc.discoveryService.DiscoverAll(ctx); err != nil {
		bc.logger.Error("tool discovery failed", "error", err)
	}
	bc.discoveryService.StartPeriodicRetry(context.Background())
	bc.discoveryService.StartPeriodicFullRediscovery(context.Background())

	bc.toolCount = bc.toolCache.Count()
	bc.logger.Info("tool discovery complete", "tools", bc.toolCount)

	return nil
}

// defaultClientFactory returns a ClientFactory that creates MCPClient instances
// based on the upstream type.
func defaultClientFactory(cfg *config.OSSConfig) service.ClientFactory {
	return func(u *upstream.Upstream) (outbound.MCPClient, error) {
		switch u.Type {
		case upstream.UpstreamTypeStdio:
			client := mcpclient.NewStdioClient(u.Command, u.Args...)
			if len(u.Env) > 0 {
				// L-68: Filter out dangerous env vars that could compromise the subprocess.
				filtered := make(map[string]string, len(u.Env))
				for k, v := range u.Env {
					switch strings.ToUpper(k) {
					case "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH":
						slog.Warn("blocked dangerous env var for upstream", "upstream", u.ID, "var", k)
					default:
						filtered[k] = v
					}
				}
				client.SetEnv(filtered)
			}
			return client, nil
		case upstream.UpstreamTypeHTTP:
			httpTimeout, err := time.ParseDuration(cfg.Upstream.HTTPTimeout)
			if err != nil {
				httpTimeout = 30 * time.Second
			}
			// H-1: Enable SSRF protection to prevent DNS rebinding attacks at connect time.
			return mcpclient.NewHTTPClient(u.URL, mcpclient.WithTimeout(httpTimeout), mcpclient.WithSSRFProtection()), nil
		default:
			return nil, fmt.Errorf("unsupported upstream type: %s", u.Type)
		}
	}
}
