package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

// TelemetryConfig configures OpenTelemetry stdout export (OSS).
type TelemetryConfig struct {
	Enabled     bool   `json:"enabled"`
	ServiceName string `json:"service_name"`
}

// DefaultTelemetryConfig returns sensible defaults.
func DefaultTelemetryConfig() TelemetryConfig {
	return TelemetryConfig{
		Enabled:     false,
		ServiceName: "sentinelgate",
	}
}

// TelemetryService manages OpenTelemetry tracing and metrics export to stdout.
type TelemetryService struct {
	mu             sync.RWMutex
	config         TelemetryConfig
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	tracer         trace.Tracer
	meter          metric.Meter
	logger         *slog.Logger

	// Metrics instruments
	toolCallCounter  metric.Int64Counter
	toolCallDuration metric.Float64Histogram
	denyCounter      metric.Int64Counter
	approvalCounter  metric.Int64Counter

	// Event bus subscription
	eventBus event.Bus
	unsubAll func()
}

// NewTelemetryService creates a new telemetry service.
func NewTelemetryService(cfg TelemetryConfig, logger *slog.Logger) (*TelemetryService, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "sentinelgate"
	}
	s := &TelemetryService{
		config: cfg,
		logger: logger,
	}
	if cfg.Enabled {
		if err := s.initProviders(context.Background()); err != nil {
			return nil, fmt.Errorf("init telemetry providers: %w", err)
		}
	}
	return s, nil
}

func (s *TelemetryService) initProviders(ctx context.Context) error {
	cfg := s.config

	res, err := resource.New(ctx,
		resource.WithAttributes(
			attribute.String("service.name", cfg.ServiceName),
			attribute.String("service.version", "2.5.0"),
		),
	)
	if err != nil {
		return fmt.Errorf("create resource: %w", err)
	}

	traceExporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		return fmt.Errorf("create stdout trace exporter: %w", err)
	}

	metricExporter, err := stdoutmetric.New()
	if err != nil {
		return fmt.Errorf("create stdout metric exporter: %w", err)
	}

	s.tracerProvider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(s.tracerProvider)

	s.meterProvider = sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExporter, sdkmetric.WithInterval(15*time.Second))),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(s.meterProvider)

	s.tracer = s.tracerProvider.Tracer("sentinelgate")
	s.meter = s.meterProvider.Meter("sentinelgate")

	s.toolCallCounter, err = s.meter.Int64Counter("sg.tool_calls.total",
		metric.WithDescription("Total number of tool calls processed"),
		metric.WithUnit("{call}"))
	if err != nil {
		return fmt.Errorf("create tool_calls counter: %w", err)
	}

	s.toolCallDuration, err = s.meter.Float64Histogram("sg.tool_calls.duration",
		metric.WithDescription("Tool call processing duration"),
		metric.WithUnit("ms"))
	if err != nil {
		return fmt.Errorf("create tool_calls duration: %w", err)
	}

	s.denyCounter, err = s.meter.Int64Counter("sg.tool_calls.denied",
		metric.WithDescription("Total denied tool calls"),
		metric.WithUnit("{call}"))
	if err != nil {
		return fmt.Errorf("create denied counter: %w", err)
	}

	s.approvalCounter, err = s.meter.Int64Counter("sg.approvals.total",
		metric.WithDescription("Total approval requests"),
		metric.WithUnit("{request}"))
	if err != nil {
		return fmt.Errorf("create approvals counter: %w", err)
	}

	s.logger.Info("telemetry stdout export enabled", "service", cfg.ServiceName)
	return nil
}

// shutdownProviders gracefully shuts down existing providers using the given context.
func (s *TelemetryService) shutdownProviders(ctx context.Context) {
	if s.tracerProvider != nil {
		_ = s.tracerProvider.Shutdown(ctx)
		s.tracerProvider = nil
	}
	if s.meterProvider != nil {
		_ = s.meterProvider.Shutdown(ctx)
		s.meterProvider = nil
	}
	s.tracer = nil
	s.meter = nil
	s.toolCallCounter = nil
	s.toolCallDuration = nil
	s.denyCounter = nil
	s.approvalCounter = nil
}

// SetConfig updates the telemetry configuration with hot-reload.
func (s *TelemetryService) SetConfig(cfg TelemetryConfig) error {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "sentinelgate"
	}

	s.mu.Lock()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	s.shutdownProviders(shutdownCtx)
	shutdownCancel()
	s.config = cfg

	var busToSubscribe event.Bus
	var oldUnsub func()

	if cfg.Enabled {
		if err := s.initProviders(context.Background()); err != nil {
			s.config.Enabled = false
			s.mu.Unlock()
			return fmt.Errorf("re-init telemetry: %w", err)
		}
		if s.eventBus != nil {
			busToSubscribe = s.eventBus
			oldUnsub = s.unsubAll
			s.unsubAll = nil
		}
	} else {
		s.logger.Info("telemetry disabled")
	}
	s.mu.Unlock()

	// M-40: Subscribe new handler BEFORE unsubscribing old to avoid event loss window.
	// Brief duplicate delivery is acceptable and harmless (idempotent metrics).
	if busToSubscribe != nil {
		unsub := busToSubscribe.SubscribeAll(func(ctx context.Context, evt event.Event) {
			s.handleEvent(ctx, evt)
		})
		s.mu.Lock()
		s.unsubAll = unsub
		s.mu.Unlock()
	}
	if oldUnsub != nil {
		oldUnsub()
	}

	return nil
}

// RecordToolCall records a tool call span and metrics.
func (s *TelemetryService) RecordToolCall(ctx context.Context, identityID, toolName, decision string, latencyUs int64, driftScore float64) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.config.Enabled || s.tracer == nil {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.String("sg.identity_id", identityID),
		attribute.String("sg.tool_name", toolName),
		attribute.String("sg.decision", decision),
		attribute.Float64("sg.drift_score", driftScore),
	}

	_, span := s.tracer.Start(ctx, "sg.tool_call",
		trace.WithAttributes(attrs...),
		trace.WithSpanKind(trace.SpanKindServer),
	)
	span.End()

	metricAttrs := metric.WithAttributes(
		attribute.String("tool", toolName),
		attribute.String("decision", decision),
		attribute.String("identity", identityID),
	)

	s.toolCallCounter.Add(ctx, 1, metricAttrs)
	s.toolCallDuration.Record(ctx, float64(latencyUs)/1000.0, metricAttrs)

	if decision == "deny" || decision == "blocked" {
		s.denyCounter.Add(ctx, 1, metricAttrs)
	}
}

// RecordApproval records an approval event.
func (s *TelemetryService) RecordApproval(ctx context.Context, identityID, toolName, outcome string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.config.Enabled || s.approvalCounter == nil {
		return
	}

	s.approvalCounter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("identity", identityID),
		attribute.String("tool", toolName),
		attribute.String("outcome", outcome),
	))
}

// SubscribeToBus subscribes to the event bus and records telemetry for relevant events.
// M-30: Always save the bus reference so a later SetConfig(enabled=true) can subscribe.
func (s *TelemetryService) SubscribeToBus(bus event.Bus) {
	s.mu.Lock()
	if bus == nil {
		s.mu.Unlock()
		return
	}
	s.eventBus = bus
	if !s.config.Enabled {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	unsub := bus.SubscribeAll(func(ctx context.Context, evt event.Event) {
		s.handleEvent(ctx, evt)
	})

	s.mu.Lock()
	s.unsubAll = unsub
	s.mu.Unlock()
}

func (s *TelemetryService) handleEvent(ctx context.Context, evt event.Event) {
	switch evt.Type {
	case "approval.hold", "approval.approved", "approval.rejected", "approval.timeout":
		p, ok := evt.Payload.(map[string]interface{})
		if !ok {
			return
		}
		identity, _ := p["identity_name"].(string)
		tool, _ := p["tool_name"].(string)
		outcome := "hold"
		switch evt.Type {
		case "approval.approved":
			outcome = "approved"
		case "approval.rejected":
			outcome = "rejected"
		case "approval.timeout":
			outcome = "timeout"
		}
		s.RecordApproval(ctx, identity, tool, outcome)
	}
}

// Config returns the current telemetry configuration.
func (s *TelemetryService) Config() TelemetryConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// Shutdown gracefully shuts down telemetry providers.
func (s *TelemetryService) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.unsubAll != nil {
		s.unsubAll()
		s.unsubAll = nil
	}

	var errs []error
	if s.tracerProvider != nil {
		if err := s.tracerProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("trace provider shutdown: %w", err))
		}
		s.tracerProvider = nil
	}
	if s.meterProvider != nil {
		if err := s.meterProvider.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("meter provider shutdown: %w", err))
		}
		s.meterProvider = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	s.logger.Info("telemetry providers shut down")
	return nil
}
