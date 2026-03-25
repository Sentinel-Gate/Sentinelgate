package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/memory"
	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
)

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
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return nil, fmt.Errorf("failed to create audit file directory %s: %w", filepath.Dir(path), err)
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to open audit file %s: %w", path, err)
		}
		// Ownership of the fd transfers to the audit store from this point.
		// MemoryAuditStore.Close() will Sync+Close the file (L-8).
		// Guard against any future code added between OpenFile and return:
		// if store construction were to fail, we must not leak the fd.
		store := memory.NewAuditStoreWithWriter(f, cfg.Audit.BufferSize)
		if store == nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to create audit store for file %s", path)
		}
		logger.Debug("audit output: file", "path", path, "buffer_size", cfg.Audit.BufferSize)
		return store, nil

	default:
		return nil, fmt.Errorf("invalid audit output: %s (must be 'stdout' or 'file://path')", cfg.Audit.Output)
	}
}

// parseLogLevel converts a string log level to slog.Level.
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

// printBanner prints a formatted startup banner to stderr.
func printBanner(version, httpAddr string, upstreamCount, connectedCount, toolCount, ruleCount int) {
	const (
		reset = "\033[0m"
		bold  = "\033[1m"
		cyan  = "\033[36m"
		dim   = "\033[2m"
	)

	adminURL := fmt.Sprintf("http://localhost%s/admin", httpAddr)
	if !strings.HasPrefix(httpAddr, ":") {
		adminURL = fmt.Sprintf("http://%s/admin", httpAddr)
	}

	proxyURL := fmt.Sprintf("http://localhost%s/mcp", httpAddr)
	if !strings.HasPrefix(httpAddr, ":") {
		proxyURL = fmt.Sprintf("http://%s/mcp", httpAddr)
	}

	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  %s%s SentinelGate %s%s\n", bold, cyan, version, reset)
	fmt.Fprintf(os.Stderr, "  %s─────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Admin UI:", adminURL)
	fmt.Fprintf(os.Stderr, "  %-14s %s\n", "Proxy:", proxyURL)
	fmt.Fprintf(os.Stderr, "  %-14s %d connected / %d configured\n", "Upstreams:", connectedCount, upstreamCount)
	fmt.Fprintf(os.Stderr, "  %-14s %d discovered\n", "Tools:", toolCount)
	fmt.Fprintf(os.Stderr, "  %-14s %d active\n", "Rules:", ruleCount)
	fmt.Fprintf(os.Stderr, "  %s─────────────────────────────────────%s\n", dim, reset)
	fmt.Fprintf(os.Stderr, "\n")
}
