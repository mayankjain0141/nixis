package otel_test

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	nixisotel "github.com/mayankjain0141/nixis/internal/otel"
)

// buildTestProviders returns in-memory trace + metric providers and an exporter
// that can be inspected after test calls. Returned shutdown must be called in cleanup.
func buildTestProviders(t *testing.T) (
	traceExp *tracetest.InMemoryExporter,
	manualReader *sdkmetric.ManualReader,
	shutdown func(context.Context) error,
) {
	t.Helper()

	traceExp = tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(traceExp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	manualReader = sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(manualReader))

	var err error
	shutdown, err = nixisotel.InitializeWithProviders(tp, mp)
	if err != nil {
		t.Fatalf("InitializeWithProviders: %v", err)
	}
	return
}

func TestOTel_SpanCreatedPerEval(t *testing.T) {
	traceExp, _, shutdown := buildTestProviders(t)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	ctx := context.Background()
	nixisotel.RecordEvaluation(ctx, "Bash", "sess-1", "allow", "cel", 1234, false)
	nixisotel.RecordEvaluation(ctx, "Read", "sess-2", "deny", "ifc", 5678, true)

	spans := traceExp.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
}

func TestOTel_SpanAttributes(t *testing.T) {
	traceExp, _, shutdown := buildTestProviders(t)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	ctx := context.Background()
	nixisotel.RecordEvaluation(ctx, "Bash", "sess-abc", "allow", "adapter", 9999, false)

	spans := traceExp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}
	span := spans[0]

	want := map[string]string{
		"nixis.tool":            "Bash",
		"nixis.session_id":      "sess-abc",
		"nixis.decision":        "allow",
		"nixis.enforcing_layer": "adapter",
	}
	attrMap := make(map[string]attribute.Value, len(span.Attributes))
	for _, a := range span.Attributes {
		attrMap[string(a.Key)] = a.Value
	}
	for k, v := range want {
		got, ok := attrMap[k]
		if !ok {
			t.Errorf("missing attribute %q", k)
			continue
		}
		if got.AsString() != v {
			t.Errorf("attribute %q: want %q, got %q", k, v, got.AsString())
		}
	}
	if _, ok := attrMap["nixis.latency_ns"]; !ok {
		t.Error("missing attribute nixis.latency_ns")
	}
}

func TestOTel_DenySpanEvent(t *testing.T) {
	traceExp, _, shutdown := buildTestProviders(t)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	ctx := context.Background()
	// denied=true must produce an "nixis.deny" span event.
	nixisotel.RecordEvaluation(ctx, "Write", "sess-x", "deny", "cel", 100, true)

	spans := traceExp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}
	events := spans[0].Events
	if len(events) == 0 {
		t.Fatal("expected span event for deny, got none")
	}
	if events[0].Name != "nixis.deny" {
		t.Errorf("expected event name 'nixis.deny', got %q", events[0].Name)
	}
}

func TestOTel_NoDenySpanEventWhenAllowed(t *testing.T) {
	traceExp, _, shutdown := buildTestProviders(t)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	ctx := context.Background()
	// denied=false must NOT produce a deny event.
	nixisotel.RecordEvaluation(ctx, "Read", "sess-y", "allow", "adapter", 50, false)

	spans := traceExp.GetSpans()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}
	if len(spans[0].Events) != 0 {
		t.Errorf("expected no span events for allowed decision, got %d", len(spans[0].Events))
	}
}

func TestOTel_MetricIncrement(t *testing.T) {
	_, manualReader, shutdown := buildTestProviders(t)
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	ctx := context.Background()
	nixisotel.RecordEvaluation(ctx, "Bash", "sess-1", "allow", "cel", 500000, false)

	var rm metricdata.ResourceMetrics
	if err := manualReader.Collect(ctx, &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	var found bool
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "nixis_evaluation_duration_seconds" {
				found = true
				h, ok := m.Data.(metricdata.Histogram[float64])
				if !ok {
					t.Fatalf("expected Histogram[float64], got %T", m.Data)
				}
				if len(h.DataPoints) == 0 {
					t.Fatal("histogram has no data points")
				}
				if h.DataPoints[0].Count != 1 {
					t.Errorf("expected count=1, got %d", h.DataPoints[0].Count)
				}
			}
		}
	}
	if !found {
		t.Error("nixis_evaluation_duration_seconds metric not found")
	}
}

func TestOTel_NoopWhenDisabled(t *testing.T) {
	// Reset to noop state — call Initialize with Enabled=false.
	shutdown, err := nixisotel.Initialize(nixisotel.Config{Enabled: false})
	if err != nil {
		t.Fatalf("Initialize disabled: %v", err)
	}
	defer func() { _ = shutdown(context.Background()) }()

	ctx := context.Background()
	allocs := testing.AllocsPerRun(100, func() {
		nixisotel.RecordEvaluation(ctx, "Bash", "sess1", "allow", "cel", 1000, false)
	})
	if allocs > 0 {
		t.Errorf("expected 0 allocs when disabled, got %v", allocs)
	}
}

func TestOTel_GracefulShutdown(t *testing.T) {
	_, _, shutdown := buildTestProviders(t)

	ctx := context.Background()
	if err := shutdown(ctx); err != nil {
		t.Errorf("shutdown returned error: %v", err)
	}
}
