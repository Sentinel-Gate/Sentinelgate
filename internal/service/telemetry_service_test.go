package service

import (
	"context"
	"log/slog"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

func TestNewTelemetryService_Disabled(t *testing.T) {
	svc, err := NewTelemetryService(DefaultTelemetryConfig(), slog.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc.config.Enabled {
		t.Error("expected disabled")
	}
	// RecordToolCall should be a no-op when disabled
	svc.RecordToolCall(context.Background(), "agent-1", "read_file", "allow", 100, 0.0)
}

func TestNewTelemetryService_StdoutExporter(t *testing.T) {
	cfg := TelemetryConfig{Enabled: true, ServiceName: "test-sg"}
	svc, err := NewTelemetryService(cfg, slog.Default())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer svc.Shutdown(context.Background())

	if svc.tracer == nil {
		t.Error("expected tracer to be initialized")
	}
	if svc.meter == nil {
		t.Error("expected meter to be initialized")
	}
}

func TestRecordToolCall_Enabled(t *testing.T) {
	svc, err := NewTelemetryService(TelemetryConfig{Enabled: true, ServiceName: "test"}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown(context.Background())

	svc.RecordToolCall(context.Background(), "agent-1", "read_file", "allow", 500, 0.1)
	svc.RecordToolCall(context.Background(), "agent-1", "write_file", "deny", 200, 0.0)
}

func TestRecordApproval(t *testing.T) {
	svc, err := NewTelemetryService(TelemetryConfig{Enabled: true, ServiceName: "test"}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown(context.Background())

	svc.RecordApproval(context.Background(), "agent-1", "delete_db", "approved")
	svc.RecordApproval(context.Background(), "agent-1", "delete_db", "rejected")
}

func TestSubscribeToBus(t *testing.T) {
	svc, err := NewTelemetryService(TelemetryConfig{Enabled: true, ServiceName: "test"}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown(context.Background())

	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()

	svc.SubscribeToBus(bus)

	bus.Publish(context.Background(), event.Event{
		Type:   "approval.approved",
		Source: "test",
		Payload: map[string]interface{}{
			"identity_name": "agent-1",
			"tool_name":     "delete_db",
		},
	})
}

func TestTelemetryConfig_Default(t *testing.T) {
	cfg := DefaultTelemetryConfig()
	if cfg.Enabled {
		t.Error("expected disabled by default")
	}
	if cfg.ServiceName != "sentinelgate" {
		t.Errorf("expected sentinelgate, got %s", cfg.ServiceName)
	}
}

func TestTelemetryShutdown_Disabled(t *testing.T) {
	svc, _ := NewTelemetryService(DefaultTelemetryConfig(), slog.Default())
	if err := svc.Shutdown(context.Background()); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSubscribeToBus_NilBus(t *testing.T) {
	svc, err := NewTelemetryService(TelemetryConfig{Enabled: true, ServiceName: "test"}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown(context.Background())
	svc.SubscribeToBus(nil)
}

func TestSetConfig_EnableDisable(t *testing.T) {
	svc, err := NewTelemetryService(DefaultTelemetryConfig(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Shutdown(context.Background())

	// Enable
	if err := svc.SetConfig(TelemetryConfig{Enabled: true, ServiceName: "test"}); err != nil {
		t.Fatalf("enable failed: %v", err)
	}
	if svc.tracer == nil {
		t.Error("expected tracer after enable")
	}

	// Record should work
	svc.RecordToolCall(context.Background(), "a", "t", "allow", 1, 0)

	// Disable
	if err := svc.SetConfig(TelemetryConfig{Enabled: false}); err != nil {
		t.Fatalf("disable failed: %v", err)
	}
	if svc.tracer != nil {
		t.Error("expected nil tracer after disable")
	}

	// Record should be no-op
	svc.RecordToolCall(context.Background(), "a", "t", "allow", 1, 0)
}

func TestSetConfig_DefaultServiceName(t *testing.T) {
	svc, _ := NewTelemetryService(DefaultTelemetryConfig(), slog.Default())
	defer svc.Shutdown(context.Background())

	if err := svc.SetConfig(TelemetryConfig{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	cfg := svc.Config()
	if cfg.ServiceName != "sentinelgate" {
		t.Errorf("expected default service name, got %s", cfg.ServiceName)
	}
}
