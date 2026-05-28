// Package otel provides 4-signal OpenTelemetry observability for Aegis:
// traces, span events, structured logs, and metrics.
//
// Zero-alloc invariant (INV-006): when OTel is disabled, noop providers are
// used and RecordEvaluation allocates nothing on the hot path.
package otel

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	otelapi "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// Config controls OTel initialization.
type Config struct {
	Enabled      bool
	Endpoint     string        // OTLP gRPC endpoint; default "localhost:4317"
	ServiceName  string        // default "aegis-daemon"
	BatchTimeout time.Duration // default 5s
}

func (c *Config) endpoint() string {
	if c.Endpoint == "" {
		return "localhost:4317"
	}
	return c.Endpoint
}

func (c *Config) serviceName() string {
	if c.ServiceName == "" {
		return "aegis-daemon"
	}
	return c.ServiceName
}

func (c *Config) batchTimeout() time.Duration {
	if c.BatchTimeout == 0 {
		return 5 * time.Second
	}
	return c.BatchTimeout
}

// Package-level providers and instruments — noop by default (INV-006: zero alloc when disabled).
// resetToNoop() must keep these in sync with the noop meter below.
var (
	globalTracer trace.Tracer = tracenoop.NewTracerProvider().Tracer("aegis")
	globalMeter  metric.Meter = noop.NewMeterProvider().Meter("aegis")
	globalLogger *slog.Logger = slog.Default()
)

func init() {
	// Pre-register noop instruments so evalDuration is never nil.
	_ = initMetrics()
}

// Initialize sets up the 4-signal OTel providers.
// Returns a shutdown function that flushes and closes all exporters.
// When cfg.Enabled is false, all globals are reset to noop and shutdown is a no-op.
func Initialize(cfg Config) (shutdown func(context.Context) error, err error) {
	if !cfg.Enabled {
		resetToNoop()
		otelEnabled = false
		return func(context.Context) error { return nil }, nil
	}

	tp, err := buildTracerProvider(cfg)
	if err != nil {
		return nil, err
	}

	mp, err := buildMeterProvider(cfg)
	if err != nil {
		_ = tp.Shutdown(context.Background())
		return nil, err
	}

	globalTracer = tp.Tracer("aegis")
	globalMeter = mp.Meter("aegis")
	otelEnabled = true

	// Signal 3: route slog to OTel OTLP logs.
	globalLogger = slog.New(otelslog.NewHandler("aegis"))

	if err := initMetrics(); err != nil {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
		return nil, err
	}

	return func(ctx context.Context) error {
		traceErr := tp.Shutdown(ctx)
		metricErr := mp.Shutdown(ctx)
		if traceErr != nil {
			return traceErr
		}
		return metricErr
	}, nil
}

// InitializeWithProviders wires externally-constructed SDK providers.
// Used by tests to inject in-memory exporters without network dependencies.
func InitializeWithProviders(tp *sdktrace.TracerProvider, mp *sdkmetric.MeterProvider) (func(context.Context) error, error) {
	globalTracer = tp.Tracer("aegis")
	globalMeter = mp.Meter("aegis")
	otelEnabled = true

	if err := initMetrics(); err != nil {
		return nil, err
	}

	return func(ctx context.Context) error {
		traceErr := tp.Shutdown(ctx)
		metricErr := mp.Shutdown(ctx)
		if traceErr != nil {
			return traceErr
		}
		return metricErr
	}, nil
}

// Tracer returns the package-level tracer (noop when OTel is disabled).
func Tracer() trace.Tracer { return globalTracer }

// Meter returns the package-level meter (noop when OTel is disabled).
func Meter() metric.Meter { return globalMeter }

// SlogHandler returns an slog.Handler that routes to OTel OTLP logs.
func SlogHandler() slog.Handler { return globalLogger.Handler() }

// tracingEnabled is true when the global tracer is a real (non-noop) SDK tracer.
// Checked atomically-safe via the otelEnabled flag set during Initialize.
var otelEnabled bool

// RecordEvaluation records a single policy evaluation as span + metrics.
// ZERO ALLOC when OTel is disabled (noop tracer) — INV-006.
func RecordEvaluation(ctx context.Context, tool, sessionID, decision, layer string, latencyNs int64, denied bool) {
	if !otelEnabled {
		return
	}
	ctx, span := globalTracer.Start(ctx, "aegis.evaluate",
		trace.WithAttributes(
			attribute.String("aegis.tool", tool),
			attribute.String("aegis.session_id", sessionID),
			attribute.String("aegis.decision", decision),
			attribute.String("aegis.enforcing_layer", layer),
			attribute.Int64("aegis.latency_ns", latencyNs),
		),
	)
	defer span.End()

	if denied {
		span.AddEvent("aegis.deny", trace.WithAttributes(
			attribute.String("aegis.decision", decision),
		))
	}

	evalDuration.Record(ctx, float64(latencyNs)/1e9)
}

// buildTracerProvider constructs an SDK TracerProvider with OTLP gRPC export.
func buildTracerProvider(cfg Config) (*sdktrace.TracerProvider, error) {
	ctx := context.Background()
	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(cfg.endpoint()),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := buildResource(cfg)
	if err != nil {
		return nil, err
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp,
			sdktrace.WithBatchTimeout(cfg.batchTimeout()),
		),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otelapi.SetTracerProvider(tp)
	return tp, nil
}

// buildMeterProvider constructs an SDK MeterProvider with OTLP gRPC export.
func buildMeterProvider(cfg Config) (*sdkmetric.MeterProvider, error) {
	ctx := context.Background()
	exp, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(cfg.endpoint()),
		otlpmetricgrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	res, err := buildResource(cfg)
	if err != nil {
		return nil, err
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)),
		sdkmetric.WithResource(res),
	)
	otelapi.SetMeterProvider(mp)
	return mp, nil
}

// buildResource constructs the OTel resource with service name.
func buildResource(cfg Config) (*sdkresource.Resource, error) {
	return sdkresource.New(context.Background(),
		sdkresource.WithAttributes(
			semconv.ServiceName(cfg.serviceName()),
		),
	)
}

// resetToNoop restores all package-level globals to noop values.
// Called when Initialize is invoked with Enabled=false so that any previous
// real providers (e.g., set by tests) do not leave live instruments behind.
func resetToNoop() {
	noopMeter := noop.NewMeterProvider().Meter("aegis")
	globalTracer = tracenoop.NewTracerProvider().Tracer("aegis")
	globalMeter = noopMeter
	globalLogger = slog.Default()
	// Reset metric instruments so RecordEvaluation skips the nil check fast path.
	evalDuration, _ = noopMeter.Float64Histogram("aegis_evaluation_duration_seconds")
	auditBufferUtil, _ = noopMeter.Float64ObservableGauge("aegis_audit_buffer_utilization")
	policyReloadTotal, _ = noopMeter.Int64Counter("aegis_policy_reload_total")
	auditDropped, _ = noopMeter.Int64Counter("aegis_audit_events_dropped_total")
	daemonConns, _ = noopMeter.Int64UpDownCounter("aegis_daemon_active_connections")
	streamClients, _ = noopMeter.Int64UpDownCounter("aegis_stream_clients_connected")
	streamDropped, _ = noopMeter.Int64Counter("aegis_stream_tap_dropped_total")
	failOpenTotal, _ = noopMeter.Int64Counter("aegis_failopen_total")
	gitleaksMemory, _ = noopMeter.Int64ObservableGauge("aegis_gitleaks_memory_bytes")
}
