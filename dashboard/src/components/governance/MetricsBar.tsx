import { useGovernanceStore } from '../../stores/governance-store';
import { useMetricsStore } from '../../stores/metrics-store';
import { useStreamStore } from '../../stores/stream-store';
import type { ConnectionState } from '../../types/events';

const CONNECTION_LABELS: Record<ConnectionState, string> = {
  IDLE: 'Idle',
  CONNECTING: 'Connecting',
  CONNECTED: 'Connected',
  DISCONNECTED: 'Disconnected',
  RECONNECTING: 'Reconnecting',
};

const CONNECTION_COLORS: Record<ConnectionState, string> = {
  IDLE: '#57606a',
  CONNECTING: '#d29922',
  CONNECTED: '#2da44e',
  DISCONNECTED: '#cf222e',
  RECONNECTING: '#d29922',
};

function nsToMs(ns: number): number {
  return ns / 1_000_000;
}

export function MetricsBar() {
  const connectionState = useStreamStore((s) => s.connectionState);

  // Read raw samples and rate window rather than calling methods in selectors
  // (calling computed methods in selectors creates new objects every render → infinite loop).
  const latencySamples = useMetricsStore((s) => s.latencySamples);
  const rateWindow = useMetricsStore((s) => s.rateWindow);

  const totalDenials = useGovernanceStore((s) => s.totalDenials);
  const totalAllows = useGovernanceStore((s) => s.totalAllows);

  // Compute derived values outside selectors.
  const eventsPerSec = computeEventsPerSec(rateWindow);
  const p95Ns = computeP95(latencySamples);
  const p95Ms = nsToMs(p95Ns);

  const totalEvents = totalDenials + totalAllows;
  const denyRatePct = totalEvents > 0 ? Math.round((totalDenials / totalEvents) * 100) : 0;

  const denyHighlight = denyRatePct > 10;
  const latencyHighlight = p95Ms > 5;
  const connColor = CONNECTION_COLORS[connectionState];

  return (
    <div style={styles.bar} role="status" aria-label="Dashboard metrics">
      <div style={styles.item}>
        <span style={styles.label}>Connection</span>
        <span
          style={{ ...styles.dot, backgroundColor: connColor }}
          aria-hidden="true"
        />
        <span style={{ ...styles.value, color: connColor }}>
          {CONNECTION_LABELS[connectionState]}
        </span>
      </div>

      <div style={styles.divider} aria-hidden="true" />

      <div style={styles.item}>
        <span style={styles.label}>Events/sec</span>
        <span style={styles.value}>{eventsPerSec.toFixed(1)}</span>
      </div>

      <div style={styles.divider} aria-hidden="true" />

      <div style={styles.item}>
        <span style={styles.label}>Deny rate (30s)</span>
        <span
          style={{
            ...styles.value,
            color: denyHighlight ? '#cf222e' : '#e6edf3',
            fontWeight: denyHighlight ? 700 : 400,
          }}
          data-high-deny={denyHighlight ? 'true' : 'false'}
        >
          {denyRatePct}%
        </span>
      </div>

      <div style={styles.divider} aria-hidden="true" />

      <div style={styles.item}>
        <span style={styles.label}>P95 latency</span>
        <span
          style={{
            ...styles.value,
            color: latencyHighlight ? '#d29922' : '#e6edf3',
            fontWeight: latencyHighlight ? 700 : 400,
          }}
        >
          {p95Ms.toFixed(2)}ms
        </span>
      </div>
    </div>
  );
}

function computeP95(samples: readonly number[]): number {
  if (samples.length === 0) return 0;
  const sorted = [...samples].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length * 0.95)] ?? 0;
}

function computeEventsPerSec(rateWindow: ReadonlyMap<number, number>): number {
  const now = Math.floor(Date.now() / 1000);
  let total = 0;
  for (let s = now - 5; s <= now; s++) {
    total += rateWindow.get(s) ?? 0;
  }
  return total / 6;
}

const styles = {
  bar: {
    display: 'flex',
    alignItems: 'center',
    padding: '6px 16px',
    background: '#161b22',
    borderBottom: '1px solid #21262d',
    fontFamily: 'ui-monospace, Consolas, monospace',
    fontSize: '12px',
    flexShrink: 0,
    minHeight: '32px',
  },
  item: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    padding: '0 12px',
  },
  label: {
    color: '#57606a',
    userSelect: 'none' as const,
    whiteSpace: 'nowrap' as const,
  },
  value: {
    color: '#e6edf3',
    whiteSpace: 'nowrap' as const,
  },
  dot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    flexShrink: 0,
  },
  divider: {
    width: '1px',
    height: '16px',
    background: '#21262d',
    flexShrink: 0,
  },
} as const;
