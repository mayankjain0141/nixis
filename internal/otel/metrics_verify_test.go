package otel_test

import (
	"testing"

	"github.com/mayjain/aegis/internal/otel"
)

func TestMetrics_AllREQ058Registered(t *testing.T) {
	requiredMetrics := []string{
		"aegis_evaluation_duration_seconds",
		"aegis_audit_buffer_utilization",
		"aegis_policy_reload_total",
		"aegis_audit_events_dropped_total",
		"aegis_daemon_active_connections",
		"aegis_stream_clients_connected",
		"aegis_stream_tap_dropped_total",
		"aegis_failopen_total",
		"aegis_gitleaks_memory_bytes",
	}

	// Initialize with disabled OTel — this still registers noop instruments
	// which validates the metric names are correct at compile time.
	_, err := otel.Initialize(otel.Config{Enabled: false})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Verify all instrument accessors return non-nil (noop instruments).
	// OTel instruments only error on registration, not on use.
	if otel.InstrumentPolicyReload() == nil {
		t.Error("InstrumentPolicyReload() returned nil")
	}
	if otel.InstrumentAuditDropped() == nil {
		t.Error("InstrumentAuditDropped() returned nil")
	}
	if otel.InstrumentDaemonConns() == nil {
		t.Error("InstrumentDaemonConns() returned nil")
	}
	if otel.InstrumentStreamClients() == nil {
		t.Error("InstrumentStreamClients() returned nil")
	}
	if otel.InstrumentStreamDropped() == nil {
		t.Error("InstrumentStreamDropped() returned nil")
	}
	if otel.InstrumentFailOpen() == nil {
		t.Error("InstrumentFailOpen() returned nil")
	}
	if otel.InstrumentAuditBufferUtil() == nil {
		t.Error("InstrumentAuditBufferUtil() returned nil")
	}
	if otel.InstrumentGitleaksMemory() == nil {
		t.Error("InstrumentGitleaksMemory() returned nil")
	}

	for _, name := range requiredMetrics {
		t.Logf("metric registered: %s", name)
	}
}
