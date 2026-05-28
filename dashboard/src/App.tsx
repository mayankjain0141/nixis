import { useEffect, useRef } from 'react';
import { MetricsBar } from './components/governance/MetricsBar';
import { EventStream } from './components/governance/EventStream';
import { CommandPalette } from './components/shell/CommandPalette';
import { useGovernanceStore } from './stores/governance-store';
import { useMetricsStore } from './stores/metrics-store';
import { useStreamStore } from './stores/stream-store';
import { usePolicyStore } from './stores/policy-store';
import { useUIStore } from './stores/ui-store';
import { createMockStreamGenerator } from './mocks/streamGenerator';
import type { Verdict } from './types/events';
import type { LabelState } from './types/events';

// Check if daemon is reachable; fall back to mock generator when offline.
const DAEMON_WS_URL = (() => {
  try {
    return import.meta.env.VITE_DAEMON_WS_URL ?? 'ws://localhost:9090/ws';
  } catch {
    return 'ws://localhost:9090/ws';
  }
})();

function isVerdictValue(v: string): v is Verdict {
  return v === 'deny' || v === 'allow' || v === 'require_approval' || v === 'audit';
}

function isLabelStateValue(v: string): v is LabelState {
  return v === 'fresh' || v === 'escalated' || v === 'tainted_by_secret' || v === 'declassified';
}

export default function App() {
  const appendEvent = useGovernanceStore((s) => s.appendEvent);
  const updateLabel = useGovernanceStore((s) => s.updateLabel);
  const recordLatency = useMetricsStore((s) => s.recordLatency);
  const recordEvent = useMetricsStore((s) => s.recordEvent);
  const setConnectionState = useStreamStore((s) => s.setConnectionState);
  const connectionState = useStreamStore((s) => s.connectionState);
  const policies = usePolicyStore((s) => s.policies);
  const bundleStatus = usePolicyStore((s) => s.bundleStatus);
  const setCommandPaletteOpen = useUIStore((s) => s.setCommandPaletteOpen);
  const wsRef = useRef<WebSocket | null>(null);
  const mockGenRef = useRef<ReturnType<typeof createMockStreamGenerator> | null>(null);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setCommandPaletteOpen(true);
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [setCommandPaletteOpen]);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let useMock = false;

    function startMock() {
      useMock = true;
      const gen = createMockStreamGenerator(50);
      mockGenRef.current = gen;
      gen.onEvent((e) => {
        if (!isVerdictValue(e.action)) return;
        const labelState: LabelState = 'fresh';
        appendEvent({
          id: `mock-${e.aegisSequence}`,
          sessionId: e.sessionId,
          tool: e.tool,
          verdict: e.action,
          reason: e.reason,
          policyId: 'mock-policy',
          enforcingLayer: 'mock',
          label: e.label,
          labelState,
          latencyNs: Math.floor(Math.random() * 5_000_000),
          aegisSequence: e.aegisSequence,
          timestamp: e.timestamp,
        });
        recordLatency(Math.floor(Math.random() * 5_000_000));
        recordEvent(Date.now());
        updateLabel(e.sessionId, e.label, labelState);
      });
      gen.start();
    }

    function tryConnect() {
      setConnectionState('CONNECTING');
      ws = new WebSocket(DAEMON_WS_URL);
      wsRef.current = ws;

      const timeout = setTimeout(() => {
        if (ws && ws.readyState !== WebSocket.OPEN) {
          ws.close();
          setConnectionState('DISCONNECTED');
          startMock();
        }
      }, 2000);

      ws.onopen = () => {
        clearTimeout(timeout);
        setConnectionState('CONNECTED');
      };

      ws.onmessage = (ev: MessageEvent<string>) => {
        try {
          const msg = JSON.parse(ev.data) as Record<string, unknown>;
          if (msg['type'] !== 'governance.decision') return;
          const verdict = msg['verdict'];
          const labelStateRaw = msg['labelState'];
          if (typeof verdict !== 'string' || !isVerdictValue(verdict)) return;
          const labelState: LabelState = typeof labelStateRaw === 'string' && isLabelStateValue(labelStateRaw)
            ? labelStateRaw
            : 'fresh';

          const label = (msg['label'] as { confidentiality: number; integrity: number; categories: number }) ?? {
            confidentiality: 0,
            integrity: 0,
            categories: 0,
          };
          const latencyNs = typeof msg['latencyNs'] === 'number' ? msg['latencyNs'] : 0;
          const timestamp = typeof msg['timestamp'] === 'number' ? msg['timestamp'] : Date.now() * 1_000_000;

          appendEvent({
            id: String(msg['id'] ?? crypto.randomUUID()),
            sessionId: String(msg['sessionId'] ?? ''),
            tool: String(msg['tool'] ?? ''),
            verdict,
            reason: String(msg['reason'] ?? ''),
            policyId: String(msg['policyId'] ?? ''),
            enforcingLayer: String(msg['enforcingLayer'] ?? ''),
            label,
            labelState,
            latencyNs,
            aegisSequence: typeof msg['aegisSequence'] === 'number' ? msg['aegisSequence'] : 0,
            timestamp,
          });

          recordLatency(latencyNs);
          recordEvent(Date.now());
          updateLabel(String(msg['sessionId'] ?? ''), label, labelState);
        } catch {
          // Malformed message — skip.
        }
      };

      ws.onerror = () => {
        clearTimeout(timeout);
        if (!useMock) {
          setConnectionState('DISCONNECTED');
          startMock();
        }
      };

      ws.onclose = () => {
        clearTimeout(timeout);
        if (!useMock) {
          setConnectionState('DISCONNECTED');
          startMock();
        }
      };
    }

    tryConnect();

    return () => {
      ws?.close();
      mockGenRef.current?.stop();
    };
  }, [appendEvent, updateLabel, recordLatency, recordEvent, setConnectionState]);

  return (
    <div style={styles.shell}>
      <CommandPalette />
      <MetricsBar />
      <div style={styles.body}>
        <aside style={styles.sidebar} aria-label="Connection and policy summary">
          <ConnectionStatus state={connectionState} />
          <PolicyList policies={policies} bundleStatus={bundleStatus} />
        </aside>

        <main style={styles.center} aria-label="Live event stream">
          <EventStream />
        </main>

        <aside style={styles.inspector} aria-label="Inspector panel (coming soon)">
          <div style={styles.inspectorPlaceholder}>
            <span style={styles.placeholderText}>Inspector</span>
            <span style={styles.placeholderSub}>WS-23</span>
          </div>
        </aside>
      </div>
    </div>
  );
}

function ConnectionStatus({ state }: { state: string }) {
  const colors: Record<string, string> = {
    IDLE: '#57606a',
    CONNECTING: '#d29922',
    CONNECTED: '#2da44e',
    DISCONNECTED: '#cf222e',
    RECONNECTING: '#d29922',
  };
  const color = colors[state] ?? '#57606a';

  return (
    <div style={sidebarStyles.section}>
      <div style={sidebarStyles.sectionTitle}>Daemon</div>
      <div style={sidebarStyles.statusRow}>
        <span style={{ ...sidebarStyles.dot, backgroundColor: color }} aria-hidden="true" />
        <span style={{ ...sidebarStyles.statusText, color }}>{state}</span>
      </div>
    </div>
  );
}

interface PolicyListProps {
  policies: Array<{ id: string; name: string; layer: string; enabled: boolean }>;
  bundleStatus: { version: number; policyCount: number; signatureVerified: boolean } | null;
}

function PolicyList({ policies, bundleStatus }: PolicyListProps) {
  return (
    <div style={sidebarStyles.section}>
      <div style={sidebarStyles.sectionTitle}>
        Policies
        {bundleStatus && (
          <span style={sidebarStyles.bundleVersion}>v{bundleStatus.version}</span>
        )}
      </div>
      {policies.length === 0 ? (
        <div style={sidebarStyles.empty}>No policies loaded</div>
      ) : (
        <ul style={sidebarStyles.list} aria-label="Active policies">
          {policies.map((p) => (
            <li key={p.id} style={sidebarStyles.policyItem}>
              <span
                style={{
                  ...sidebarStyles.enabledDot,
                  backgroundColor: p.enabled ? '#2da44e' : '#57606a',
                }}
                aria-hidden="true"
              />
              <span style={sidebarStyles.policyName} title={p.name}>{p.name}</span>
              <span style={sidebarStyles.layerBadge}>{p.layer}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

const styles = {
  shell: {
    display: 'flex',
    flexDirection: 'column' as const,
    height: '100vh',
    width: '100vw',
    background: '#0d1117',
    color: '#e6edf3',
    fontFamily: 'ui-sans-serif, system-ui, sans-serif',
    overflow: 'hidden',
  },
  body: {
    display: 'flex',
    flex: 1,
    overflow: 'hidden',
    gap: '1px',
    background: '#21262d',
  },
  sidebar: {
    width: '220px',
    flexShrink: 0,
    background: '#0d1117',
    overflowY: 'auto' as const,
    borderRight: '1px solid #21262d',
  },
  center: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column' as const,
    background: '#0d1117',
    overflow: 'hidden',
    padding: '12px',
  },
  inspector: {
    width: '280px',
    flexShrink: 0,
    background: '#0d1117',
    borderLeft: '1px solid #21262d',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
  },
  inspectorPlaceholder: {
    display: 'flex',
    flexDirection: 'column' as const,
    alignItems: 'center',
    gap: '4px',
  },
  placeholderText: {
    color: '#30363d',
    fontSize: '14px',
    fontWeight: 600,
  },
  placeholderSub: {
    color: '#21262d',
    fontSize: '11px',
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
} as const;

const sidebarStyles = {
  section: {
    padding: '12px',
    borderBottom: '1px solid #21262d',
  },
  sectionTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
    color: '#57606a',
    fontSize: '11px',
    fontWeight: 600,
    textTransform: 'uppercase' as const,
    letterSpacing: '0.08em',
    marginBottom: '8px',
  },
  bundleVersion: {
    color: '#30363d',
    fontSize: '10px',
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
  statusRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  },
  dot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    flexShrink: 0,
  },
  statusText: {
    fontSize: '12px',
    fontFamily: 'ui-monospace, Consolas, monospace',
  },
  empty: {
    color: '#30363d',
    fontSize: '11px',
    fontStyle: 'italic' as const,
  },
  list: {
    listStyle: 'none',
    margin: 0,
    padding: 0,
    display: 'flex',
    flexDirection: 'column' as const,
    gap: '4px',
  },
  policyItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '6px',
  },
  enabledDot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    flexShrink: 0,
  },
  policyName: {
    color: '#8b949e',
    fontSize: '11px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap' as const,
    flex: 1,
  },
  layerBadge: {
    color: '#30363d',
    fontSize: '9px',
    fontFamily: 'ui-monospace, Consolas, monospace',
    flexShrink: 0,
  },
} as const;
