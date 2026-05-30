package integration_test

import (
	"context"
	"testing"

	"go.uber.org/goleak"

	"github.com/mayankjain0141/nixis/internal/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// otelReader is an in-memory metric reader shared across all tests in this package.
// Initialized once in TestMain before any test goroutine starts — no race with
// otel.initMetrics() writes from goroutines spawned by tests (e.g. reload watcher AfterFunc).
var otelReader *sdkmetric.ManualReader

// collectMetrics returns the set of metric names accumulated in otelReader.
func collectMetrics(t *testing.T) map[string]bool {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := otelReader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("otelReader.Collect: %v", err)
	}
	found := make(map[string]bool)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			found[m.Name] = true
		}
	}
	return found
}

func TestMain(m *testing.M) {
	// Initialize OTel with an in-memory exporter once, before any test runs.
	// This eliminates the data race between otel.initMetrics() (global writes) and
	// the reload watcher's time.AfterFunc goroutine (reads policyReloadTotal).
	otelReader = sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(otelReader))
	tp := sdktrace.NewTracerProvider()
	shutdown, err := otel.InitializeWithProviders(tp, mp)
	if err != nil {
		panic("otel.InitializeWithProviders: " + err.Error())
	}
	defer func() { _ = shutdown(context.Background()) }()

	goleak.VerifyTestMain(m)
}
