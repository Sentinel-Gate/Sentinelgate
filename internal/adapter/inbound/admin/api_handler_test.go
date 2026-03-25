package admin

import (
	"context"
	"log/slog"
	"sync"
	"testing"
)

// captureHandler is a slog.Handler that records all log records for test assertions.
type captureHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}
func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

func (h *captureHandler) Records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	dst := make([]slog.Record, len(h.records))
	copy(dst, h.records)
	return dst
}

// TestTrustedProxies_LoggerOrderIndependence verifies that WithTrustedProxies
// warnings are emitted to the configured logger regardless of option ordering (CONCERN-01).
// This ensures that even if WithTrustedProxies is applied BEFORE WithAPILogger,
// the warning for an invalid CIDR goes to the custom logger, not slog.Default().
func TestTrustedProxies_LoggerOrderIndependence(t *testing.T) {
	capture := &captureHandler{}
	customLogger := slog.New(capture)

	// Key: WithTrustedProxies BEFORE WithAPILogger — the bug scenario.
	h := NewAdminAPIHandler(
		WithTrustedProxies([]string{"10.0.0.0/8", "not-a-cidr", "172.16.0.0/12"}),
		WithAPILogger(customLogger),
	)

	// Valid CIDRs should still be parsed correctly.
	if len(h.trustedProxies) != 2 {
		t.Fatalf("expected 2 valid trusted proxies, got %d", len(h.trustedProxies))
	}

	// The warning for "not-a-cidr" should have been logged to the custom logger.
	records := capture.Records()
	if len(records) != 1 {
		t.Fatalf("expected 1 warning record in custom logger, got %d", len(records))
	}

	if records[0].Level != slog.LevelWarn {
		t.Errorf("expected Warn level, got %v", records[0].Level)
	}
	if records[0].Message != "invalid trusted proxy CIDR, skipping" {
		t.Errorf("unexpected message: %q", records[0].Message)
	}

	// Verify the "cidr" attribute contains the invalid value.
	found := false
	records[0].Attrs(func(a slog.Attr) bool {
		if a.Key == "cidr" && a.Value.String() == "not-a-cidr" {
			found = true
			return false
		}
		return true
	})
	if !found {
		t.Error("expected cidr=not-a-cidr attribute in log record")
	}

	// Verify pendingProxyCIDRs was cleared.
	if h.pendingProxyCIDRs != nil {
		t.Error("expected pendingProxyCIDRs to be nil after construction")
	}
}

// TestTrustedProxies_ValidCIDRs_NoWarnings verifies that valid CIDRs
// produce no log warnings and are parsed correctly.
func TestTrustedProxies_ValidCIDRs_NoWarnings(t *testing.T) {
	capture := &captureHandler{}
	customLogger := slog.New(capture)

	h := NewAdminAPIHandler(
		WithAPILogger(customLogger),
		WithTrustedProxies([]string{"10.0.0.0/8", "192.168.0.0/16"}),
	)

	if len(h.trustedProxies) != 2 {
		t.Fatalf("expected 2 trusted proxies, got %d", len(h.trustedProxies))
	}

	records := capture.Records()
	if len(records) != 0 {
		t.Errorf("expected 0 warnings for valid CIDRs, got %d", len(records))
	}
}

// TestTrustedProxies_Empty verifies that no CIDRs produces no warnings and
// an empty trustedProxies list.
func TestTrustedProxies_Empty(t *testing.T) {
	capture := &captureHandler{}
	customLogger := slog.New(capture)

	h := NewAdminAPIHandler(
		WithTrustedProxies([]string{}),
		WithAPILogger(customLogger),
	)

	if len(h.trustedProxies) != 0 {
		t.Fatalf("expected 0 trusted proxies, got %d", len(h.trustedProxies))
	}

	records := capture.Records()
	if len(records) != 0 {
		t.Errorf("expected 0 warnings, got %d", len(records))
	}
}
