import { useEffect, useRef } from 'react';
import { AnimatePresence } from 'framer-motion';
import { MetricsBar } from './components/governance/MetricsBar';
import { EventStreamCanvas } from './components/governance/EventStreamCanvas';
import { LatticeHasseDiagram } from './components/governance/LatticeHasseDiagram';
import { ThreatTimeline } from './components/governance/ThreatTimeline';
import { GovernanceDAG } from './components/governance/dag/GovernanceDAG';
import { DelegationTree } from './components/governance/DelegationTree';
import { AuditHashChain } from './components/governance/AuditHashChain';
import { DenyColorGuard } from './services/DenyColorGuard';
import { CommandPalette } from './components/shell/CommandPalette';
import { Inspector } from './components/shell/Inspector';
import { useGovernanceStore } from './stores/governance-store';
import { useMetricsStore } from './stores/metrics-store';
import { useStreamStore } from './stores/stream-store';
import type { InvariantViolation } from './stores/stream-store';
import { usePolicyStore } from './stores/policy-store';
import { useUIStore } from './stores/ui-store';
import { useLatticeStore } from './stores/lattice-store';
import { useThreatStore } from './stores/threat-store';
import { createMockStreamGenerator } from './mocks/streamGenerator';
import { runDemoScenario } from './mocks/demoScenario';
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
          // Use named policies from the event when available (demo scenario and daemon both send them).
          // Fall back to synthetic entries only when the bundle carries no policy list.
          const namedPolicies: import('./stores/policy-store').PolicySummary[] =
            Array.isArray(b.policies) && b.policies.length > 0
              ? b.policies.map((p: { id: string; enabled: boolean; layer: string; cel_expression?: string }) => ({
                  id: p.id,
                  name: p.id.replace(/^aegis\//, ''),
                  layer: (p.layer ?? 'cel') as 'cel' | 'ifc' | 'adapter' | 'delegation' | 'secret-scan',
                  enabled: p.enabled ?? true,
                  bundleVersion: b.version,
                  celExpression: p.cel_expression,
                }))
              : Array.from({ length: b.policyCount }, (_, i) => ({
                  id: `policy-${b.version}-${i}`,
                  name: `Policy ${i + 1}`,
                  layer: 'cel' as const,
                  enabled: true,
                  bundleVersion: b.version,
                }));
          setPolicies(namedPolicies);
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
  const inspectorOpen = useUIStore((s) => s.inspectorOpen);

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

  // Watch for command palette mock requests and activate/deactivate mock mode.
  useEffect(() => {
    const unsubMock = useStreamStore.subscribe((state, prevState) => {
      if (state.requestMockMode === prevState.requestMockMode) return;
      if (state.requestMockMode) {
        useStreamStore.getState().setConnectionState('MOCK');
        if (mockGenRef.current === null) {
          // Run scripted demo scenario via custom event (pipeline not available here).
          const cancelDemo = runDemoScenario(
            (json) => {
              window.dispatchEvent(new CustomEvent('aegis:mock-event', { detail: json }));
            },
            () => {
              const gen = createMockStreamGenerator(8);
              gen.onEvent((e) => {
                mockSeqRef.current++;
                const raw = mockEventToCloudEvent(e, mockSeqRef.current);
                window.dispatchEvent(new CustomEvent('aegis:mock-event', { detail: raw }));
              });
              gen.start();
              mockGenRef.current = gen;
            },
          );
          mockGenRef.current = { stop: cancelDemo } as ReturnType<typeof createMockStreamGenerator>;
        }
      } else {
        mockGenRef.current?.stop();
        mockGenRef.current = null;
        useStreamStore.getState().setConnectionState('IDLE');
      }
    });
    return () => unsubMock();
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
      getStreamBundleVersion: () => usePolicyStore.getState().bundleStatus?.version ?? null,
    });

    const interval = setInterval(() => {
      const violations = checker.runAll().filter(r => !r.passed);
      if (violations.length > 0) {
        useStreamStore.getState().recordInvariantViolations(
          violations.map((v): InvariantViolation => ({ id: v.id, evidence: { severity: v.severity, message: v.message } })),
        );
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
      // Under backpressure, ALLOW evaluations are coalesced into summary counts.
      // Individual GovernanceEvents are intentionally not stored for coalesced batches
      // to preserve memory bounds. Only immediateEvents (CRITICAL + HIGH priority) are
      // stored verbatim. coalescedCount is tracked in stream-store for operator visibility.
      const coalescedTotal = (batch.coalescedSummary ?? []).reduce((s, c) => s + c.count, 0);
      if (coalescedTotal > 0) {
        useStreamStore.getState().recordCoalesced(coalescedTotal);
      }
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

    // CRITICAL: Register message handler BEFORE calling connect() to avoid race condition.
    // The daemon sends state.snapshot + bundle.activated immediately on connect.
    // If we register the handler after connect(), those messages arrive before
    // the handler is registered and are silently dropped, causing "No policies loaded".
    const unsubMsg = wsManager.onMessage((raw, meta) => {
      pipeline.ingest(raw, meta);
    });

    let stateCheckInterval: ReturnType<typeof setInterval> | null = null;
    let useMock = false;

    function startMock() {
      if (useMock) return;
      useMock = true;
      setConnectionState('MOCK');
      // Play the scripted demo scenario first, then fall back to random events.
      const cancelDemo = runDemoScenario(
        (json) => {
          pipeline.ingest(json, { receivedAt: performance.now() });
        },
        () => {
          // Demo finished — start random background events at a slow rate.
          const gen = createMockStreamGenerator(8);
          mockGenRef.current = gen;
          gen.onEvent((e: StreamEvent) => {
            mockSeqRef.current++;
            const raw = mockEventToCloudEvent(e, mockSeqRef.current);
            pipeline.ingest(raw, { receivedAt: performance.now() });
          });
          gen.start();
        },
      );
      // Store cancel in mockGenRef via a shim so cleanup works.
      mockGenRef.current = { stop: cancelDemo } as ReturnType<typeof createMockStreamGenerator>;
    }

    // Forward mock events dispatched by the requestMockMode subscriber into the live pipeline.
    function handleMockEvent(e: Event) {
      const raw = (e as CustomEvent<string>).detail;
      pipeline.ingest(raw, { receivedAt: performance.now() });
    }
    window.addEventListener('aegis:mock-event', handleMockEvent);

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
      window.removeEventListener('aegis:mock-event', handleMockEvent);
    };
  }, [appendEvent, updateLabel, recordLatency, recordEvent, setConnectionState, updateLastSequence, setBundleStatus, setPolicies]);

  return (
    <div style={styles.shell}>
      <DenyColorGuard />
      <CommandPalette />
      <MetricsBar />
      <div style={styles.body}>
        <aside style={styles.sidebar} aria-label="Connection and policy summary">
          <ConnectionStatus state={connectionState} />
          <PolicyList policies={policies} bundleStatus={bundleStatus} />
          <div style={sidebarStyles.section}>
            <div style={sidebarStyles.sectionTitle}>IFC Sessions</div>
            <LatticeHasseDiagram />
          </div>
          <details style={{ marginTop: 8 }}>
            <summary style={{ cursor: 'pointer', color: '#8b949e', fontSize: 12, padding: '4px 12px' }}>Delegation Tree</summary>
            <DelegationTree />
          </details>
          <details style={{ marginTop: 8 }}>
            <summary style={{ cursor: 'pointer', color: '#8b949e', fontSize: 12, padding: '4px 12px' }}>Audit Hash Chain</summary>
            <AuditHashChain />
          </details>
        </aside>

        <main style={styles.center} aria-label="Live event stream">
          <EventStreamCanvas />
          <details style={{ marginTop: 8 }}>
            <summary style={{ cursor: 'pointer', color: '#8b949e', fontSize: 12 }}>Governance DAG</summary>
            <GovernanceDAG />
          </details>
        </main>

        <aside style={styles.inspector} aria-label="Inspector panel">
          <div style={styles.inspectorInner}>
            <div style={styles.inspectorTop}>
              <AnimatePresence>
                {inspectorOpen && <Inspector key="inspector" />}
              </AnimatePresence>
            </div>
            <ThreatTimeline />
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
    MOCK: '#8b5cf6',
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
    flexDirection: 'column' as const,
    overflow: 'hidden',
  },
  inspectorInner: {
    display: 'flex',
    flexDirection: 'column' as const,
    flex: 1,
    overflow: 'hidden',
  },
  inspectorTop: {
    flex: 1,
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column' as const,
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
