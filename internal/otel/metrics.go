// SPDX-License-Identifier: MIT
package otel

import "go.opentelemetry.io/otel/metric"

// All instruments are registered once at Initialize time (REQ-058).
//
// Observable gauges (auditBufferUtil, gitleaksMemory) are registered here and
// their values updated via RegisterCallback by package users — the gauge
// handles are kept in the package so callers can pass them to RegisterCallback.
var (
	evalDuration      metric.Float64Histogram
	auditBufferUtil   metric.Float64ObservableGauge
	policyReloadTotal metric.Int64Counter
	auditDropped      metric.Int64Counter
	daemonConns       metric.Int64UpDownCounter
	streamClients     metric.Int64UpDownCounter
	streamDropped     metric.Int64Counter
	failOpenTotal     metric.Int64Counter
	gitleaksMemory    metric.Int64ObservableGauge
)

// initMetrics registers all REQ-058 instruments against globalMeter.
// Called after globalMeter is set in Initialize / InitializeWithProviders.
func initMetrics() error {
	var err error

	evalDuration, err = globalMeter.Float64Histogram(
		"aegis_evaluation_duration_seconds",
		metric.WithDescription("Policy evaluation latency in seconds"),
	)
	if err != nil {
		return err
	}

	auditBufferUtil, err = globalMeter.Float64ObservableGauge(
		"aegis_audit_buffer_utilization",
		metric.WithDescription("Fraction of the audit write channel that is full (0–1)"),
	)
	if err != nil {
		return err
	}

	policyReloadTotal, err = globalMeter.Int64Counter(
		"aegis_policy_reload_total",
		metric.WithDescription("Total policy reload attempts, labeled by status"),
	)
	if err != nil {
		return err
	}

	auditDropped, err = globalMeter.Int64Counter(
		"aegis_audit_events_dropped_total",
		metric.WithDescription("Audit events dropped due to a full write channel"),
	)
	if err != nil {
		return err
	}

	daemonConns, err = globalMeter.Int64UpDownCounter(
		"aegis_daemon_active_connections",
		metric.WithDescription("Number of active connections to the daemon"),
	)
	if err != nil {
		return err
	}

	streamClients, err = globalMeter.Int64UpDownCounter(
		"aegis_stream_clients_connected",
		metric.WithDescription("Number of connected stream tap clients"),
	)
	if err != nil {
		return err
	}

	streamDropped, err = globalMeter.Int64Counter(
		"aegis_stream_tap_dropped_total",
		metric.WithDescription("Stream tap events dropped due to slow consumers"),
	)
	if err != nil {
		return err
	}

	failOpenTotal, err = globalMeter.Int64Counter(
		"aegis_failopen_total",
		metric.WithDescription("Total fail-open events, labeled by reason"),
	)
	if err != nil {
		return err
	}

	gitleaksMemory, err = globalMeter.Int64ObservableGauge(
		"aegis_gitleaks_memory_bytes",
		metric.WithDescription("Memory used by the gitleaks scanner in bytes"),
	)
	if err != nil {
		return err
	}

	return nil
}

// Instrument accessors for callers that record non-evaluation metrics directly.

// InstrumentPolicyReload returns the policy reload counter (noop when OTel disabled).
func InstrumentPolicyReload() metric.Int64Counter { return policyReloadTotal }

// InstrumentAuditDropped returns the audit dropped counter (noop when OTel disabled).
func InstrumentAuditDropped() metric.Int64Counter { return auditDropped }

// InstrumentDaemonConns returns the daemon connections gauge (noop when OTel disabled).
func InstrumentDaemonConns() metric.Int64UpDownCounter { return daemonConns }

// InstrumentStreamClients returns the stream clients gauge (noop when OTel disabled).
func InstrumentStreamClients() metric.Int64UpDownCounter { return streamClients }

// InstrumentStreamDropped returns the stream dropped counter (noop when OTel disabled).
func InstrumentStreamDropped() metric.Int64Counter { return streamDropped }

// InstrumentFailOpen returns the fail-open counter (noop when OTel disabled).
func InstrumentFailOpen() metric.Int64Counter { return failOpenTotal }

// InstrumentAuditBufferUtil returns the audit buffer gauge for callback registration.
func InstrumentAuditBufferUtil() metric.Float64ObservableGauge { return auditBufferUtil }

// InstrumentGitleaksMemory returns the gitleaks memory gauge for callback registration.
func InstrumentGitleaksMemory() metric.Int64ObservableGauge { return gitleaksMemory }
