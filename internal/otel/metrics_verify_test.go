package otel_test

import (
	"context"
	"testing"

	"github.com/mayankjain0141/nixis/internal/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestMetrics_AllREQ058Registered(t *testing.T) {
	// Use ManualReader to collect registered metrics
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	tp := sdktrace.NewTracerProvider()

	shutdown, err := otel.InitializeWithProviders(tp, mp)
	if err != nil {
		t.Fatalf("InitializeWithProviders: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	// Trigger metric registration by calling RecordEvaluation once
	// This ensures the histogram is actually used, not just declared
	otel.RecordEvaluation(context.Background(), "test", "sess", "allow", "adapter", 1000, false)

	// Also trigger counter increments to ensure they're registered
	if counter := otel.InstrumentPolicyReload(); counter != nil {
		counter.Add(context.Background(), 1)
	}
	if counter := otel.InstrumentAuditDropped(); counter != nil {
		counter.Add(context.Background(), 1)
	}
	if counter := otel.InstrumentStreamDropped(); counter != nil {
		counter.Add(context.Background(), 1)
	}
	if counter := otel.InstrumentFailOpen(); counter != nil {
		counter.Add(context.Background(), 1)
	}
	if gauge := otel.InstrumentDaemonConns(); gauge != nil {
		gauge.Add(context.Background(), 1)
	}
	if gauge := otel.InstrumentStreamClients(); gauge != nil {
		gauge.Add(context.Background(), 1)
	}

	// Collect metrics
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Build set of registered metric names
	registered := make(map[string]bool)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			registered[m.Name] = true
			t.Logf("metric found: %s", m.Name)
		}
	}

	// REQ-058 required metrics
	required := []string{
		"nixis_evaluation_duration_seconds",
		"nixis_policy_reload_total",
		"nixis_audit_events_dropped_total",
		"nixis_daemon_active_connections",
		"nixis_stream_clients_connected",
		"nixis_stream_tap_dropped_total",
		"nixis_failopen_total",
	}

	for _, name := range required {
		if !registered[name] {
			t.Errorf("metric %q not registered", name)
		}
	}

	// Observable gauges (nixis_audit_buffer_utilization, nixis_gitleaks_memory_bytes)
	// are registered but only emit data when a callback is registered.
	// Verify their instrument accessors return non-nil.
	if otel.InstrumentAuditBufferUtil() == nil {
		t.Error("InstrumentAuditBufferUtil() returned nil")
	}
	if otel.InstrumentGitleaksMemory() == nil {
		t.Error("InstrumentGitleaksMemory() returned nil")
	}
}
