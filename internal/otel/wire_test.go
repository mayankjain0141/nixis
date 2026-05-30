// SPDX-License-Identifier: MIT
package otel_test

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	nixisotel "github.com/mayankjain0141/nixis/internal/otel"
)

// TestOTel_FullWire verifies that after InitializeWithProviders, a RecordEvaluation
// call produces a span AND a metric data point (not noop drops).
func TestOTel_FullWire(t *testing.T) {
	spanExporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(spanExporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	shutdown, err := nixisotel.InitializeWithProviders(tp, mp)
	if err != nil {
		t.Fatalf("InitializeWithProviders: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = shutdown(ctx)
	}()

	nixisotel.RecordEvaluation(context.Background(), "Bash", "test-sess-001", "deny", "cel", 150_000, true)

	spans := spanExporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least 1 span, got 0 — RecordEvaluation did not produce a span")
	}
	found := false
	for _, s := range spans {
		if s.Name == "nixis.evaluate" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no 'nixis.evaluate' span found in %d spans: %v", len(spans), spans)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect metrics: %v", err)
	}
	foundMetric := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "nixis_evaluation_duration_seconds" {
				foundMetric = true
			}
		}
	}
	if !foundMetric {
		t.Logf("Available metrics:")
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				t.Logf("  %s", m.Name)
			}
		}
		t.Error("nixis_evaluation_duration_seconds not found — metric was not emitted after RecordEvaluation")
	}
}

// TestOTel_InstrumentDaemonConns_NotNoop verifies the daemon connection counter
// actually records data after InitializeWithProviders.
func TestOTel_InstrumentDaemonConns_NotNoop(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))

	spanExporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(spanExporter))

	shutdown, err := nixisotel.InitializeWithProviders(tp, mp)
	if err != nil {
		t.Fatalf("InitializeWithProviders: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = shutdown(ctx)
	}()

	nixisotel.InstrumentDaemonConns().Add(context.Background(), 1)
	nixisotel.InstrumentDaemonConns().Add(context.Background(), -1)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	found := false
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "nixis_daemon_active_connections" {
				found = true
			}
		}
	}
	if !found {
		t.Logf("Available metrics after InstrumentDaemonConns:")
		for _, sm := range rm.ScopeMetrics {
			for _, m := range sm.Metrics {
				t.Logf("  %s", m.Name)
			}
		}
		t.Error("nixis_daemon_active_connections not found — noop provider still active")
	}
}
