import { useEffect, useRef } from 'react';
import { MetricsBar } from './components/governance/MetricsBar';
import { EventStream } from './components/governance/EventStream';
import { CommandPalette } from './components/shell/CommandPalette';
import { Inspector } from './components/shell/Inspector';
import { useGovernanceStore } from './stores/governance-store';
import { useMetricsStore } from './stores/metrics-store';
import { useStreamStore } from './stores/stream-store';
import { usePolicyStore } from './stores/policy-store';
import { useUIStore } from './stores/ui-store';
import { useLatticeStore } from './stores/lattice-store';
import { useThreatStore } from './stores/threat-store';
import { createMockStreamGenerator } from './mocks/streamGenerator';
import { createWebSocketManager } from './lib/realtime/ws-manager';
import { createEventIngestionPipeline } from './lib/realtime/ingestion-pipeline';
import { createEventBus } from './lib/realtime/event-bus';
import { createBackpressureController } from './lib/realtime/backpressure';
import { createSyncOrchestrator, atomicUpdate } from './lib/realtime/sync-orchestrator';
import { createStreamProcessor } from './lib/realtime/stream-processor';
import { GovernanceInvariantChecker } from './services/invariants';
import type { ValidatedEvent } from './lib/realtime/ingestion-pipeline';
import type { GovernanceEvent } from './stores/governance-store';
import type { BundleStatus } from './stores/policy-store';
import type { StreamEvent, SecurityLabel } from './types/aegis';
import type { LabelState, ConnectionState } from './types/events';

const DAEMON_WS_URL = (() => {
  try {
    return import.meta.env.VITE_DAEMON_WS_URL ?? 'ws://localhost:9090/ws';
  } catch {
    return 'ws://localhost:9090/ws';
  }
})();

// Convert mock StreamEvent to a CloudEvent JSON string for pipeline ingestion.
function mockEventToCloudEvent(e: StreamEvent, seq: number): string {
  const eventType = (e.action === 'deny' || e.action === 'require_approval')
    ? 'policy.denied'
    : 'policy.evaluated';
  return JSON.stringify({
    specversion: '1.0',
    type: eventType,
    source: 'aegis-mock/local',
    id: `mock-${seq}`,
    time: new Date().toISOString(),
    datacontenttype: 'application/json',
    aegissequence: seq,
    data: {
      tool: e.tool,
      session_id: e.sessionId,
      decision: {
        action: e.action,
        reason: e.reason,
        policy_id: 'mock-policy',
        enforcing_layer: 'adapter',
        labels: e.label,
      },
      label_state: 'fresh',
      latency_ns: Math.floor(Math.random() * 5_000_000),
    },
  });
}

// Build an atomic cross-store update for a policy event.
// governance-store and metrics-store updated in the same apply() — WS-21 atomic cross-store invariant.
function buildPolicyUpdate(
  event: ValidatedEvent & { type: 'policy.evaluated' | 'policy.denied' },
  appendEvent: (ev: GovernanceEvent) => void,
  updateLabel: (sessionId: string, incoming: SecurityLabel, state: LabelState) => void,
  recordLatency: (ns: number) => void,
  recordEvent: (ms: number) => void,
  updateLastSequence: (seq: number) => void,
) {
  const d = event.data;
  const labelState: LabelState = (
    d.label_state === 'fresh' ||
    d.label_state === 'escalated' ||
    d.label_state === 'tainted_by_secret' ||
    d.label_state === 'declassified'
  ) ? (d.label_state as LabelState) : 'fresh';

  const govEvent: GovernanceEvent = {
    id: event.envelope.id ?? `evt-${event.envelope.aegissequence}`,
    sessionId: d.session_id,
    tool: d.tool,
    verdict: d.decision.action,
    reason: d.decision.reason,
    policyId: d.decision.policy_id,
    enforcingLayer: d.decision.enforcing_layer,
    label: d.decision.labels,
    labelState,
    latencyNs: d.latency_ns,
    aegisSequence: event.envelope.aegissequence,
    timestamp: event.envelope.time
      ? new Date(event.envelope.time).getTime() * 1_000_000
      : Date.now() * 1_000_000,
  };

  const isDeny = d.decision.action === 'deny' || d.decision.action === 'require_approval';
  const priority = isDeny ? 'IMMEDIATE' : 'FRAME';

  return atomicUpdate(priority, event.type,
    () => {
      appendEvent(govEvent);
      recordLatency(d.latency_ns);
      recordEvent(Date.now());
    },
    () => updateLabel(d.session_id, d.decision.labels, labelState),
    () => updateLastSequence(event.envelope.aegissequence),
  );
}

// Route validated events to stores via the sync-orchestrator.
// All 12 ADR-012 event types are routed; CRITICAL events use IMMEDIATE priority.
function routeEvents(
  events: ValidatedEvent[],
  orchestrator: ReturnType<typeof createSyncOrchestrator>,
  appendEvent: (ev: GovernanceEvent) => void,
  updateLabel: (sessionId: string, incoming: SecurityLabel, state: LabelState) => void,
  recordLatency: (ns: number) => void,
  recordEvent: (ms: number) => void,
  setConnectionState: (state: ConnectionState) => void,
  updateLastSequence: (seq: number) => void,
  setBundleStatus: (status: BundleStatus) => void,
  setPolicies: (policies: import('./stores/policy-store').PolicySummary[]) => void,
): void {
  for (const event of events) {
    switch (event.type) {
      case 'policy.evaluated':
      case 'policy.denied': {
        orchestrator.dispatchUpdate(buildPolicyUpdate(
          event, appendEvent, updateLabel, recordLatency, recordEvent, updateLastSequence,
        ));
        break;
      }

      case 'bundle.activated': {
        const b = event.data;
        orchestrator.dispatchUpdate(atomicUpdate('FRAME', event.type, () => {
          setBundleStatus({
            version: b.version,
            previousVersion: b.previousVersion ?? 0,
            hash: b.hash,
            signatureVerified: b.signatureVerified,
            policyCount: b.policyCount,
            adapterCount: b.adapterCount ?? 0,
            activatedAt: Date.now(),
          });
          // Populate the policy sidebar list from the policy count.
          // The daemon sends named policies when available; for startup bundles
          // loaded from a directory, we synthesise one entry per policy.
          const syntheticPolicies = Array.from({ length: b.policyCount }, (_, i) => ({
            id: `policy-${b.version}-${i}`,
            name: `Policy ${i + 1}`,
            layer: 'cel' as const,
            enabled: true,
            bundleVersion: b.version,
          }));
          setPolicies(syntheticPolicies);
          updateLastSequence(event.envelope.aegissequence);
        }));
        break;
      }

      case 'label.escalated': {
        const d = event.data;
        orchestrator.dispatchUpdate(atomicUpdate('IMMEDIATE', event.type, () => {
          useLatticeStore.getState().upsertNode(
            d.session_id,
            d.label,
            (d.label_state ?? 'escalated') as LabelState,
          );
          updateLastSequence(event.envelope.aegissequence);
        }));
        break;
      }

      case 'secret.detected':
      case 'mcp.tool_drift': {
        const d = event.data;
        const tool = 'tool' in d ? (d.tool as string) : '';
        orchestrator.dispatchUpdate(atomicUpdate('IMMEDIATE', event.type, () => {
          useThreatStore.getState().appendThreat({
            id: `threat-${event.envelope.aegissequence}`,
            type: 'secret.found',
            sessionId: 'session_id' in d ? (d.session_id as string) : '',
            tool,
            severity: 'critical',
            description: event.type,
            aegisSequence: event.envelope.aegissequence,
            timestamp: event.envelope.time
              ? new Date(event.envelope.time).getTime()
              : Date.now(),
            acknowledged: false,
          });
          updateLastSequence(event.envelope.aegissequence);
        }));
        break;
      }

      case 'system.error':
        if (event.data.severity === 'critical') {
          orchestrator.dispatchUpdate(atomicUpdate('IMMEDIATE', event.type, () => {
            setConnectionState('DISCONNECTED');
          }));
        } else {
          updateLastSequence(event.envelope.aegissequence);
        }
        break;

      case 'stream.heartbeat':
        // ws-manager handles clock offset; sequence update still needed.
        updateLastSequence(event.envelope.aegissequence);
        break;

      default:
        // delegation.created/revoked/expired, audit.checkpoint —
        // flow through stream-processor for windowed aggregations.
        updateLastSequence(event.envelope.aegissequence);
        break;
    }
  }
}

export default function App() {
  const appendEvent = useGovernanceStore((s) => s.appendEvent);
  const updateLabel = useGovernanceStore((s) => s.updateLabel);
  const recordLatency = useMetricsStore((s) => s.recordLatency);
  const recordEvent = useMetricsStore((s) => s.recordEvent);
  const setConnectionState = useStreamStore((s) => s.setConnectionState);
  const updateLastSequence = useStreamStore((s) => s.updateLastSequence);
  const connectionState = useStreamStore((s) => s.connectionState);
  const policies = usePolicyStore((s) => s.policies);
  const bundleStatus = usePolicyStore((s) => s.bundleStatus);
  const setBundleStatus = usePolicyStore((s) => s.setBundleStatus);
  const setPolicies = usePolicyStore((s) => s.setPolicies);
  const setCommandPaletteOpen = useUIStore((s) => s.setCommandPaletteOpen);

  const mockGenRef = useRef<ReturnType<typeof createMockStreamGenerator> | null>(null);
  const mockSeqRef = useRef(0);

  // Keyboard shortcut for command palette.
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

  // Handle aegis:navigate events dispatched by CommandPalette navigation commands.
  useEffect(() => {
    function handleNavigate(e: Event) {
      const panel = (e as CustomEvent<{ panel: string }>).detail?.panel;
      if (panel === 'events') {
        document.querySelector('main[aria-label="Live event stream"]')?.scrollIntoView();
      } else if (panel === 'inspector') {
        document.querySelector('[aria-label="Inspector panel"]')?.scrollIntoView();
      }
    }
    window.addEventListener('aegis:navigate', handleNavigate);
    return () => window.removeEventListener('aegis:navigate', handleNavigate);
  }, []);

  // Governance invariant checker on 5s interval.
  useEffect(() => {
    const checker = new GovernanceInvariantChecker({
      getGovernanceEvents: () => useGovernanceStore.getState().events.map(e => ({
        id: e.id,
        aegisSequence: e.aegisSequence,
        verdict: e.verdict,
      })),
      getSessionLabels: () => {
        const labels = useGovernanceStore.getState().sessionLabels;
        const out = new Map<string, { label: SecurityLabel; updatedAt: number }>();
        for (const [k, v] of labels) {
          out.set(k, { label: v.label, updatedAt: v.updatedAt });
        }
        return out;
      },
      getPolicyBundleVersion: () => usePolicyStore.getState().bundleStatus?.version ?? null,
      getStreamBundleVersion: () => null,
    });

    const interval = setInterval(() => {
      const violations = checker.runAll().filter(r => !r.passed);
      if (violations.length > 0) {
        console.warn('[aegis] invariant violations:', violations);
      }
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  // Main realtime wiring:
  // ws-manager → ingestion-pipeline → event-bus → backpressure → sync-orchestrator → stores
  //                                                                    ↓ (internally)
  //                                                             stream-processor (WS-20)
  useEffect(() => {
    const bus = createEventBus();
    const bpController = createBackpressureController();
    const streamProcessor = createStreamProcessor();
    // WS-21 consumes WS-20: orchestrator.dispatch(batch) calls streamProcessor.process(batch).
    const orchestrator = createSyncOrchestrator({ streamProcessor });

    // Backpressure output → sync-orchestrator (calls stream-processor internally) → stores.
    const unsubBp = bpController.onOutput((batch) => {
      orchestrator.dispatch(batch);
      routeEvents(
        batch.immediateEvents,
        orchestrator,
        appendEvent, updateLabel, recordLatency, recordEvent,
        setConnectionState, updateLastSequence, setBundleStatus, setPolicies,
      );
    });

    // Event bus feeds backpressure.
    const unsubBus = bus.subscribe(
      () => true,
      (events) => bpController.submit(events),
      0,
    );

    const wsManager = createWebSocketManager(DAEMON_WS_URL);
    const pipeline = createEventIngestionPipeline(wsManager);

    // Validated events go to the event bus.
    const unsubPipeline = pipeline.onValidated((event) => bus.emit(event));

    let stateCheckInterval: ReturnType<typeof setInterval> | null = null;
    let useMock = false;

    function startMock() {
      if (useMock) return;
      useMock = true;
      setConnectionState('DISCONNECTED');
      const gen = createMockStreamGenerator(50);
      mockGenRef.current = gen;
      gen.onEvent((e: StreamEvent) => {
        mockSeqRef.current++;
        const raw = mockEventToCloudEvent(e, mockSeqRef.current);
        pipeline.ingest(raw, { receivedAt: performance.now() });
      });
      gen.start();
    }

    stateCheckInterval = setInterval(() => {
      setConnectionState(wsManager.getState());
    }, 250);

    setConnectionState('CONNECTING');
    wsManager.connect();

    const fallbackTimer = setTimeout(() => {
      if (wsManager.getState() !== 'CONNECTED' && !useMock) {
        startMock();
      }
    }, 2000);

    const unsubMsg = wsManager.onMessage((raw, meta) => {
      pipeline.ingest(raw, meta);
    });

    return () => {
      clearTimeout(fallbackTimer);
      if (stateCheckInterval !== null) clearInterval(stateCheckInterval);
      wsManager.disconnect();
      unsubMsg();
      unsubPipeline();
      unsubBus();
      unsubBp();
      orchestrator.flush();
      streamProcessor.reset();
      mockGenRef.current?.stop();
      mockGenRef.current = null;
    };
  }, [appendEvent, updateLabel, recordLatency, recordEvent, setConnectionState, updateLastSequence, setBundleStatus]);

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

        <aside style={styles.inspector} aria-label="Inspector panel">
          <Inspector />
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
