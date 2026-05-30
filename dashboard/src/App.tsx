import { useCallback, useEffect, useRef } from 'react';
import { AppShell, AppHeader, AppMetricsBar } from './components/shell/AppShell';
import { PolicySidebar } from './components/shell/PolicySidebar';
import { CommandPalette } from './components/shell/CommandPalette';
import { Inspector } from './components/shell/Inspector';
import { SessionCards } from './components/shell/SessionCards';
import { MainArea, activeTabRef } from './components/shell/MainArea';
import type { MainTab } from './components/shell/MainArea';
import { DenyColorGuard } from './services/DenyColorGuard';
import { useGovernanceStore } from './stores/governance-store';
import { useMetricsStore } from './stores/metrics-store';
import { useStreamStore } from './stores/stream-store';
import type { InvariantViolation } from './stores/stream-store';
import { usePolicyStore } from './stores/policy-store';
import { useUIStore } from './stores/ui-store';
import { useLatticeStore } from './stores/lattice-store';
import { useThreatStore } from './stores/threat-store';
import { runDemoScenario, runLiveDemoScenario, getDemoPolicies } from './mocks/demoScenario';
import { getDaemonApiBase } from './lib/api';
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
import type { SecurityLabel } from './types/aegis';
import type { LabelState, ConnectionState } from './types/events';

const DAEMON_WS_URL = (() => {
  try {
    return import.meta.env.VITE_DAEMON_WS_URL ?? 'ws://localhost:9090/ws';
  } catch {
    return 'ws://localhost:9090/ws';
  }
})();

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
    celExpression: (d.decision as { cel_expression?: string }).cel_expression,
    requestArgs: (d as { request_args?: string }).request_args,
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
          const rawBundle = b as { policyCount?: number; policy_count?: number; policies?: { id: string; enabled: boolean; layer: string; cel_expression?: string }[] };
          setBundleStatus({
            version: b.version,
            previousVersion: b.previousVersion ?? 0,
            hash: b.hash,
            signatureVerified: b.signatureVerified,
            policyCount: rawBundle.policyCount ?? rawBundle.policy_count ?? 0,
            adapterCount: b.adapterCount ?? 0,
            activatedAt: Date.now(),
          });
          if (Array.isArray(rawBundle.policies) && rawBundle.policies.length > 0) {
            // Merge incoming policies into the existing list — preserves CEL expressions
            // and any policies not mentioned in this bundle event (e.g. pre-seeded demo policies).
            const incoming: import('./stores/policy-store').PolicySummary[] = rawBundle.policies.map((p) => ({
              id: p.id,
              name: p.id.replace(/^aegis\//, ''),
              layer: (p.layer ?? 'cel') as 'cel' | 'ifc' | 'adapter' | 'delegation' | 'secret-scan',
              enabled: p.enabled ?? true,
              bundleVersion: b.version,
              celExpression: p.cel_expression,
            }));
            usePolicyStore.getState().mergePolicies(incoming);
          }
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

      case 'audit.checkpoint': {
        const d = event.data;
        const seq = d.sequence ?? event.envelope.aegissequence;
        const hash = d.hash;
        const prevHash = d.prev_hash ?? d.prevHash ?? '';
        orchestrator.dispatchUpdate(atomicUpdate('FRAME', event.type, () => {
          appendEvent({
            id: event.envelope.id ?? `audit-${event.envelope.aegissequence}`,
            sessionId: 'audit',
            tool: 'audit',
            verdict: 'audit',
            reason: `Checkpoint #${seq} — ${d.events_since_prev ?? d.eventCount ?? 0} events`,
            policyId: 'audit.checkpoint',
            enforcingLayer: 'audit',
            label: { confidentiality: 0, integrity: 0, categories: 0 },
            labelState: 'fresh',
            latencyNs: 0,
            aegisSequence: event.envelope.aegissequence,
            timestamp: event.envelope.time
              ? new Date(event.envelope.time).getTime() * 1_000_000
              : Date.now() * 1_000_000,
            celExpression: `hash:${hash.slice(0, 16)} prev:${prevHash.slice(0, 16)}`,
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

      case 'delegation.created': {
        const d = event.data as { session_id?: string; delegator_id?: string; delegatee_id?: string; granted_label?: unknown; ceiling_label?: unknown; expires_at?: number };
        if (d.session_id && d.delegator_id) {
          orchestrator.dispatchUpdate(atomicUpdate('FRAME', event.type, () => {
            useGovernanceStore.getState().updateDelegationChain(d.session_id!, [{
              hopIndex: 0,
              delegatorId: d.delegator_id!,
              delegateeId: d.session_id!,
              grantedLabel: (d.granted_label as { confidentiality: number; integrity: number; categories: number }) ?? { confidentiality: 0, integrity: 0, categories: 0 },
              ceilingLabel: (d.ceiling_label as { confidentiality: number; integrity: number; categories: number }) ?? { confidentiality: 0, integrity: 0, categories: 0 },
              expiresAt: d.expires_at,
            }]);
            updateLastSequence(event.envelope.aegissequence);
          }));
        } else {
          updateLastSequence(event.envelope.aegissequence);
        }
        break;
      }

      case 'delegation.revoked':
      case 'delegation.expired': {
        const d = event.data as { session_id?: string };
        if (d.session_id) {
          orchestrator.dispatchUpdate(atomicUpdate('FRAME', event.type, () => {
            useGovernanceStore.getState().updateDelegationChain(d.session_id!, []);
            updateLastSequence(event.envelope.aegissequence);
          }));
        } else {
          updateLastSequence(event.envelope.aegissequence);
        }
        break;
      }

      case 'stream.heartbeat':
        updateLastSequence(event.envelope.aegissequence);
        break;

      default:
        updateLastSequence((event as { envelope: { aegissequence: number } }).envelope.aegissequence);
        break;
    }
  }
}

// ── Sub-components ──────────────────────────────────────────────────────────

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
  const setCommandPaletteOpen = useUIStore((s) => s.setCommandPaletteOpen);

  const mockGenRef = useRef<{ stop: () => void } | null>(null);

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
      // Tab panels — switch the secondary tab
      const tabMap: Record<string, MainTab> = {
        dag: 'dag', playground: 'playground', audit: 'audit', delegation: 'delegation', lattice: 'lattice',
      };
      if (panel && tabMap[panel]) {
        activeTabRef.setTab(tabMap[panel]);
        return;
      }
      // Scroll targets
      if (panel === 'events') {
        document.querySelector('[aria-label="Live event stream"]')?.scrollIntoView({ behavior: 'smooth' });
      } else if (panel === 'inspector') {
        document.querySelector('[aria-label="Inspector panel"]')?.scrollIntoView({ behavior: 'smooth' });
      } else if (panel === 'metrics') {
        activeTabRef.setTab('dag'); // metrics are in the DAG tab area
      } else if (panel === 'threats') {
        activeTabRef.setTab('audit'); // threats visible in audit tab
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
          // Seed policies directly — bypasses Zod pipeline so CEL expressions are guaranteed present.
          usePolicyStore.getState().setPolicies(getDemoPolicies(1));
          const cancelDemo = runDemoScenario((json) => {
            window.dispatchEvent(new CustomEvent('aegis:mock-event', { detail: json }));
          });
          mockGenRef.current = { stop: cancelDemo } as { stop: () => void };
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
        setConnectionState, updateLastSequence, setBundleStatus,
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
      // Seed policies directly — bypasses Zod pipeline so CEL expressions are guaranteed present.
      usePolicyStore.getState().setPolicies(getDemoPolicies(1));
      const cancelDemo = runDemoScenario((json) => {
        pipeline.ingest(json, { receivedAt: performance.now() });
      });
      mockGenRef.current = { stop: cancelDemo } as { stop: () => void };
    }

    function handleMockEvent(e: Event) {
      const raw = (e as CustomEvent<string>).detail;
      pipeline.ingest(raw, { receivedAt: performance.now() });
    }
    window.addEventListener('aegis:mock-event', handleMockEvent);

    function handleReconnect() {
      wsManager.disconnect();
      setConnectionState('CONNECTING');
      setTimeout(() => wsManager.connect(), 300);
    }
    window.addEventListener('aegis:reconnect', handleReconnect);

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
      window.removeEventListener('aegis:reconnect', handleReconnect);
    };
  }, [appendEvent, updateLabel, recordLatency, recordEvent, setConnectionState, updateLastSequence, setBundleStatus]);

  const handleStartDemo = useCallback(() => {
    useGovernanceStore.getState().clear?.();
    usePolicyStore.getState().setPolicies(getDemoPolicies(1));

    const apiBase = getDaemonApiBase();
    fetch(`${apiBase}/healthz`, { signal: AbortSignal.timeout(1000) })
      .then(() => {
        // Daemon is reachable — use live evaluation
        mockGenRef.current?.stop();
        mockGenRef.current = null;
        useStreamStore.getState().setConnectionState('CONNECTING');
        const cancel = runLiveDemoScenario(apiBase, (err) => console.error('demo error:', err));
        mockGenRef.current = { stop: cancel };
      })
      .catch(() => {
        // Daemon not reachable — fall back to offline mock
        console.warn('aegis-daemon not reachable — running offline demo');
        useStreamStore.getState().setConnectionState('MOCK');
        useStreamStore.getState().setRequestMockMode(false);
        setTimeout(() => useStreamStore.getState().setRequestMockMode(true), 100);
      });
  }, []);

  const handleStopDemo = useCallback(() => {
    mockGenRef.current?.stop();
    mockGenRef.current = null;
    useStreamStore.getState().setRequestMockMode(false);
    useStreamStore.getState().setConnectionState('IDLE');
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
            onStopDemo={handleStopDemo}
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
        main={<MainArea />}
        inspector={<RightPanel />}
      />
    </>
  );
}
