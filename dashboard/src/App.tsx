import { useCallback, useEffect, useRef, useState } from 'react';
import { AppShell, AppHeader, AppMetricsBar } from './components/shell/AppShell';
import { EventStreamList } from './components/governance/EventStreamList';
import { PolicySidebar } from './components/shell/PolicySidebar';
import { GovernanceDAG } from './components/governance/dag/GovernanceDAG';
import { DelegationTree } from './components/governance/DelegationTree';
import { AuditHashChain } from './components/governance/AuditHashChain';
import { CommandPalette } from './components/shell/CommandPalette';
import { Inspector } from './components/shell/Inspector';
import { SessionCards } from './components/shell/SessionCards';
import { PolicyPlayground } from './components/shell/PolicyPlayground';
import { DenyColorGuard } from './services/DenyColorGuard';
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
          const rawBundle = b as { policyCount: number; policies?: { id: string; enabled: boolean; layer: string; cel_expression?: string }[] };
          const namedPolicies: import('./stores/policy-store').PolicySummary[] =
            Array.isArray(rawBundle.policies) && rawBundle.policies!.length > 0
              ? rawBundle.policies!.map((p) => ({
                  id: p.id,
                  name: p.id.replace(/^aegis\//, ''),
                  layer: (p.layer ?? 'cel') as 'cel' | 'ifc' | 'adapter' | 'delegation' | 'secret-scan',
                  enabled: p.enabled ?? true,
                  bundleVersion: b.version,
                  celExpression: p.cel_expression,
                }))
              : Array.from({ length: rawBundle.policyCount ?? b.policyCount }, (_, i) => ({
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
        updateLastSequence(event.envelope.aegissequence);
        break;

      default:
        updateLastSequence(event.envelope.aegissequence);
        break;
    }
  }
}

// ── Sub-components ──────────────────────────────────────────────────────────

type MainTab = 'dag' | 'playground' | 'audit' | 'delegation';

function MainContent() {
  const [activeTab, setActiveTab] = useState<MainTab>('dag');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Event stream: takes 50% of height */}
      <div style={{ flex: '0 0 50%', overflow: 'hidden', borderBottom: '1px solid var(--border)' }}>
        <EventStreamList />
      </div>

      {/* Tab bar */}
      <div style={{
        display: 'flex', alignItems: 'center',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-surface)',
        padding: '0 12px', height: 36, flexShrink: 0,
      }}>
        {(['dag', 'playground', 'audit', 'delegation'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: '0 14px', height: '100%', border: 'none', cursor: 'pointer',
              background: 'transparent', fontSize: 12, fontWeight: 500,
              color: activeTab === tab ? 'var(--text-primary)' : 'var(--text-secondary)',
              borderBottom: activeTab === tab ? '2px solid var(--info-blue)' : '2px solid transparent',
              textTransform: 'uppercase' as const, letterSpacing: '0.06em',
            }}
          >
            {tab === 'dag' ? 'DAG' : tab === 'playground' ? 'Playground' : tab === 'audit' ? 'Audit Chain' : 'Delegation'}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflow: 'auto', padding: 12 }}>
        {activeTab === 'dag'        && <GovernanceDAG />}
        {activeTab === 'playground' && <PolicyPlayground />}
        {activeTab === 'audit'      && <AuditHashChain />}
        {activeTab === 'delegation' && <DelegationTree />}
      </div>
    </div>
  );
}

function RightPanel() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ flex: '0 0 55%', overflow: 'auto', borderBottom: '1px solid var(--border)' }}>
        <Inspector />
      </div>
      <div style={{ flex: 1, overflow: 'auto' }}>
        <SessionCards />
      </div>
    </div>
  );
}

// ── App root ─────────────────────────────────────────────────────────────────

export default function App() {
  const appendEvent = useGovernanceStore((s) => s.appendEvent);
  const updateLabel = useGovernanceStore((s) => s.updateLabel);
  const recordLatency = useMetricsStore((s) => s.recordLatency);
  const recordEvent = useMetricsStore((s) => s.recordEvent);
  const setConnectionState = useStreamStore((s) => s.setConnectionState);
  const updateLastSequence = useStreamStore((s) => s.updateLastSequence);
  const connectionState = useStreamStore((s) => s.connectionState);
  const coalescedCount = useStreamStore((s) => s.coalescedCount);
  const setBundleStatus = usePolicyStore((s) => s.setBundleStatus);
  const setPolicies = usePolicyStore((s) => s.setPolicies);
  const setCommandPaletteOpen = useUIStore((s) => s.setCommandPaletteOpen);

  const mockGenRef = useRef<ReturnType<typeof createMockStreamGenerator> | null>(null);
  const mockSeqRef = useRef(0);

  // Keyboard shortcut for command palette
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

  // Handle aegis:navigate events dispatched by CommandPalette
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

  // Watch for command palette mock requests and activate/deactivate mock mode
  useEffect(() => {
    const unsubMock = useStreamStore.subscribe((state, prevState) => {
      if (state.requestMockMode === prevState.requestMockMode) return;
      if (state.requestMockMode) {
        useStreamStore.getState().setConnectionState('MOCK');
        if (mockGenRef.current === null) {
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

  // Governance invariant checker on 5s interval
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

  // Main realtime wiring
  useEffect(() => {
    const bus = createEventBus();
    const bpController = createBackpressureController();
    const streamProcessor = createStreamProcessor();
    const orchestrator = createSyncOrchestrator({ streamProcessor });

    const unsubBp = bpController.onOutput((batch) => {
      orchestrator.dispatch(batch);
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

    const unsubBus = bus.subscribe(
      () => true,
      (events) => bpController.submit(events),
      0,
    );

    const wsManager = createWebSocketManager(DAEMON_WS_URL);
    const pipeline = createEventIngestionPipeline(wsManager);

    const unsubPipeline = pipeline.onValidated((event) => bus.emit(event));

    const unsubMsg = wsManager.onMessage((raw, meta) => {
      pipeline.ingest(raw, meta);
    });

    let stateCheckInterval: ReturnType<typeof setInterval> | null = null;
    let useMock = false;

    function startMock() {
      if (useMock) return;
      useMock = true;
      setConnectionState('MOCK');
      const cancelDemo = runDemoScenario(
        (json) => {
          pipeline.ingest(json, { receivedAt: performance.now() });
        },
        () => {
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
      mockGenRef.current = { stop: cancelDemo } as ReturnType<typeof createMockStreamGenerator>;
    }

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

  const handleStartDemo = useCallback(() => {
    useGovernanceStore.getState().clear?.();
    useStreamStore.getState().setConnectionState('MOCK');
    useStreamStore.getState().setRequestMockMode(false);
    setTimeout(() => useStreamStore.getState().setRequestMockMode(true), 100);
  }, []);

  // Read metrics on render (computed on demand, not stored as reactive state)
  const metricsStore = useMetricsStore.getState();
  const bucket = metricsStore.getLatencyBucket();
  const eventsPerSec = metricsStore.getEventsPerSecond();
  const totalEvents = useGovernanceStore((s) => s.totalDenials + s.totalAllows);
  const totalDenials = useGovernanceStore((s) => s.totalDenials);
  const denyRate = totalEvents > 0 ? (totalDenials / totalEvents) * 100 : 0;
  const p99LatencyMs = bucket.p99 / 1_000_000;
  const bufferPct = Math.min(100, (coalescedCount / 500) * 100);

  return (
    <>
      <DenyColorGuard />
      <CommandPalette />
      <AppShell
        header={
          <AppHeader
            connectionState={connectionState}
            onStartDemo={handleStartDemo}
            onOpenPalette={() => useUIStore.getState().setCommandPaletteOpen(true)}
          />
        }
        metricsBar={
          <AppMetricsBar
            eventsPerSec={eventsPerSec}
            denyRate={denyRate}
            p99LatencyMs={p99LatencyMs}
            bufferPct={bufferPct}
            coalescedCount={coalescedCount}
          />
        }
        sidebar={<PolicySidebar />}
        main={<MainContent />}
        inspector={<RightPanel />}
      />
    </>
  );
}
