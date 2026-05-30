import { useCallback, useEffect, useRef, useState } from 'react';
import { AppShell, AppHeader, AppMetricsBar } from './components/shell/AppShell';
import { PolicySidebar } from './components/shell/PolicySidebar';
import { PolicyPlayground } from './components/shell/PolicyPlayground';
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
import { getDaemonApiBase } from './lib/api';
import { loadPolicies } from './lib/policy-loader';
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
import type { SecurityLabel } from './types/nixis';
import type { LabelState, ConnectionState } from './types/events';

const DAEMON_WS_URL = (() => {
  try {
    return import.meta.env.VITE_DAEMON_WS_URL ?? 'ws://localhost:9090/ws';
  } catch {
    return 'ws://localhost:9090/ws';
  }
})();

const IMPACT_TEMPLATES: Record<string, string> = {
  'secret.detected.aws': 'Session escalated to Restricted. Bash and network tools now require approval.',
  'secret.detected.generic': 'Session escalated to Restricted. Tool access restricted until declassification.',
  'mcp.tool_drift': 'MCP tool definition changed unexpectedly. Possible supply-chain modification. Review tool before use.',
  'policy.denied.critical': 'Critical policy violation. The requested operation was blocked.',
};

function getImpact(threatType: string, data: Record<string, unknown>): string {
  if (threatType === 'secret.detected') {
    const key = String(data.key ?? data.secretKey ?? '');
    if (key.includes('AWS') || key.includes('aws')) return IMPACT_TEMPLATES['secret.detected.aws'];
    return IMPACT_TEMPLATES['secret.detected.generic'];
  }
  if (threatType === 'mcp.tool_drift') return IMPACT_TEMPLATES['mcp.tool_drift'];
  if (threatType === 'policy.denied') return IMPACT_TEMPLATES['policy.denied.critical'];
  return 'Potential security event. Review the details and take action if needed.';
}

function getHumanDescription(threatType: string, data: Record<string, unknown>): string {
  if (threatType === 'secret.detected') {
    const key = String(data.key ?? data.secretKey ?? data.type ?? 'Unknown');
    return `Secret Detected: ${key}`;
  }
  if (threatType === 'mcp.tool_drift') return 'MCP Tool Definition Changed';
  if (threatType === 'policy.denied') return 'Policy Violation Blocked';
  return 'Security Event';
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
    id: event.envelope.id ?? `evt-${event.envelope.nixissequence}`,
    sessionId: d.session_id,
    tool: d.tool,
    verdict: d.decision.action,
    reason: d.decision.reason,
    policyId: d.decision.policy_id,
    enforcingLayer: d.decision.enforcing_layer,
    label: d.decision.labels,
    labelState,
    latencyNs: d.latency_ns,
    nixisSequence: event.envelope.nixissequence,
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
    () => updateLastSequence(event.envelope.nixissequence),
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
        // Only fetch policies if none are loaded yet or if this is a newer bundle version.
        const storedVersion = usePolicyStore.getState().bundleStatus?.version ?? 0;
        const eventVersion = (b as { version?: number }).version ?? 0;
        if (usePolicyStore.getState().policies.length === 0 || eventVersion > storedVersion) {
          loadPolicies().then(policies => {
            if (policies.length > 0) {
              usePolicyStore.getState().setPolicies(policies);
            }
          });
        }
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
              name: p.id.replace(/^nixis\//, ''),
              layer: (p.layer ?? 'cel') as 'cel' | 'ifc' | 'adapter' | 'delegation' | 'secret-scan',
              enabled: p.enabled ?? true,
              bundleVersion: b.version,
              celExpression: p.cel_expression,
            }));
            usePolicyStore.getState().mergePolicies(incoming);
          }
          updateLastSequence(event.envelope.nixissequence);
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
          updateLastSequence(event.envelope.nixissequence);
        }));
        break;
      }

      case 'secret.detected':
      case 'mcp.tool_drift': {
        const d = event.data;
        const tool = 'tool' in d ? (d.tool as string) : '';
        const sessionId = 'session_id' in d ? (d.session_id as string) : '';
        const dataAsRecord = d as Record<string, unknown>;
        const humanDescription = getHumanDescription(event.type, dataAsRecord);
        const impact = getImpact(event.type, dataAsRecord);
        const relatedSessionName = useGovernanceStore.getState().sessionDisplayNames.get(sessionId) ?? 'Unknown Session';
        orchestrator.dispatchUpdate(atomicUpdate('IMMEDIATE', event.type, () => {
          useThreatStore.getState().appendThreat({
            id: `threat-${event.envelope.nixissequence}`,
            type: 'secret.found',
            sessionId,
            tool,
            severity: 'critical',
            description: event.type,
            nixisSequence: event.envelope.nixissequence,
            timestamp: event.envelope.time
              ? new Date(event.envelope.time).getTime()
              : Date.now(),
            acknowledged: false,
            humanDescription,
            impact,
            relatedSessionName,
          });
          updateLastSequence(event.envelope.nixissequence);
        }));
        break;
      }

      case 'audit.checkpoint': {
        const d = event.data;
        const seq = d.sequence ?? event.envelope.nixissequence;
        const hash = d.hash;
        const prevHash = d.prev_hash ?? d.prevHash ?? null;
        const eventCount = d.events_since_prev ?? d.eventCount ?? 0;
        const checkpointTimestamp = event.envelope.time
          ? new Date(event.envelope.time).getTime()
          : Date.now();
        orchestrator.dispatchUpdate(atomicUpdate('FRAME', event.type, () => {
          useGovernanceStore.getState().appendAuditCheckpoint({
            sequence: seq,
            hash,
            prevHash,
            eventCount,
            timestamp: checkpointTimestamp,
          });
          appendEvent({
            id: event.envelope.id ?? `audit-${event.envelope.nixissequence}`,
            sessionId: 'audit',
            tool: 'audit',
            verdict: 'audit',
            reason: `Checkpoint #${seq} — ${eventCount} events`,
            policyId: 'audit.checkpoint',
            enforcingLayer: 'audit',
            label: { confidentiality: 0, integrity: 0, categories: 0 },
            labelState: 'fresh',
            latencyNs: 0,
            nixisSequence: event.envelope.nixissequence,
            timestamp: checkpointTimestamp * 1_000_000,
            celExpression: `hash:${hash.slice(0, 16)} prev:${(prevHash ?? '').slice(0, 16)}`,
          });
          updateLastSequence(event.envelope.nixissequence);
        }));
        break;
      }

      case 'system.error':
        if (event.data.severity === 'critical') {
          orchestrator.dispatchUpdate(atomicUpdate('IMMEDIATE', event.type, () => {
            setConnectionState('DISCONNECTED');
          }));
        } else {
          updateLastSequence(event.envelope.nixissequence);
        }
        break;

      case 'delegation.created': {
        const d = event.data as { session_id?: string; delegator_id?: string; delegatee_id?: string; granted_label?: unknown; ceiling_label?: unknown; expires_at?: number; reason?: string; capabilities?: string[] };
        const delegateeId = d.delegatee_id ?? d.session_id;
        const delegatorId = d.delegator_id;
        if (delegateeId && delegatorId) {
          const store = useGovernanceStore.getState();
          const reason = d.reason;
          const capabilities = d.capabilities;

          // Compute display name: use reason if short, else ordinal
          const existingCount = store.sessionDisplayNames.size;
          const displayName = (reason && reason.length < 30)
            ? reason
            : `Agent ${existingCount + 1}`;

          orchestrator.dispatchUpdate(atomicUpdate('FRAME', event.type, () => {
            const gs = useGovernanceStore.getState();
            // Set root session display name if not yet assigned
            if (!gs.sessionDisplayNames.has(delegatorId)) {
              gs.setSessionDisplayName(delegatorId, 'You (main)');
            }
            gs.setSessionDisplayName(delegateeId, displayName);
            gs.updateDelegationChain(delegateeId, [{
              hopIndex: 0,
              delegatorId,
              delegateeId,
              grantedLabel: (d.granted_label as { confidentiality: number; integrity: number; categories: number }) ?? { confidentiality: 0, integrity: 0, categories: 0 },
              ceilingLabel: (d.ceiling_label as { confidentiality: number; integrity: number; categories: number }) ?? { confidentiality: 0, integrity: 0, categories: 0 },
              expiresAt: d.expires_at,
              reason,
              capabilities,
            }]);
            updateLastSequence(event.envelope.nixissequence);
          }));
        } else {
          updateLastSequence(event.envelope.nixissequence);
        }
        break;
      }

      case 'delegation.revoked':
      case 'delegation.expired': {
        const d = event.data as { session_id?: string };
        if (d.session_id) {
          orchestrator.dispatchUpdate(atomicUpdate('FRAME', event.type, () => {
            useGovernanceStore.getState().updateDelegationChain(d.session_id!, []);
            updateLastSequence(event.envelope.nixissequence);
          }));
        } else {
          updateLastSequence(event.envelope.nixissequence);
        }
        break;
      }

      case 'stream.heartbeat':
        updateLastSequence(event.envelope.nixissequence);
        break;

      default:
        updateLastSequence((event as { envelope: { nixissequence: number } }).envelope.nixissequence);
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
  const [playgroundOpen, setPlaygroundOpen] = useState(false);
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

  // Handle nixis:navigate events dispatched by CommandPalette
  useEffect(() => {
    function handleNavigate(e: Event) {
      const panel = (e as CustomEvent<{ panel: string }>).detail?.panel;
      // Tab panels — switch the secondary tab
      const tabMap: Record<string, MainTab> = {
        dag: 'dag',
        agents: 'agents',
        threats: 'threats',
        lattice: 'lattice',
        // Legacy aliases — CommandPalette may still emit these
        audit: 'agents',
        delegation: 'agents',
      };
      if (panel && tabMap[panel]) {
        activeTabRef.setTab(tabMap[panel]);
        return;
      }
    }
    window.addEventListener('nixis:navigate', handleNavigate);
    return () => window.removeEventListener('nixis:navigate', handleNavigate);
  }, []);

  // Watch for command palette mock requests and activate/deactivate mock mode
  useEffect(() => {
    const unsubMock = useStreamStore.subscribe((state, prevState) => {
      if (state.requestMockMode === prevState.requestMockMode) return;
      if (state.requestMockMode) {
        useStreamStore.getState().setConnectionState('MOCK');
        if (mockGenRef.current === null) {
          if (import.meta.env.DEV) {
            import('./mocks/demoScenario').then(({ runDemoScenario }) => {
              const cancelDemo = runDemoScenario((json) => {
                window.dispatchEvent(new CustomEvent('nixis:mock-event', { detail: json }));
              });
              mockGenRef.current = { stop: cancelDemo } as { stop: () => void };
            });
          }
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
        nixisSequence: e.nixisSequence,
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
      if (import.meta.env.DEV) {
        import('./mocks/demoScenario').then(({ runDemoScenario }) => {
          const cancelDemo = runDemoScenario((json) => {
            pipeline.ingest(json, { receivedAt: performance.now() });
          });
          mockGenRef.current = { stop: cancelDemo } as { stop: () => void };
        });
      }
    }

    function handleMockEvent(e: Event) {
      const raw = (e as CustomEvent<string>).detail;
      pipeline.ingest(raw, { receivedAt: performance.now() });
    }
    window.addEventListener('nixis:mock-event', handleMockEvent);

    function handleReconnect() {
      wsManager.disconnect();
      setConnectionState('CONNECTING');
      setTimeout(() => wsManager.connect(), 300);
    }
    window.addEventListener('nixis:reconnect', handleReconnect);

    stateCheckInterval = setInterval(() => {
      setConnectionState(wsManager.getState());
    }, 250);

    setConnectionState('CONNECTING');
    wsManager.connect();

    loadPolicies().then(policies => {
      if (policies.length > 0) {
        usePolicyStore.getState().setPolicies(policies);
      }
    });

    const fallbackTimer = setTimeout(() => {
      if (wsManager.getState() !== 'CONNECTED' && !useMock) {
        if (import.meta.env.PROD) {
          setConnectionState('ERROR');
        } else {
          console.warn('[nixis] daemon not reachable after 5s — running offline demo');
          startMock();
        }
      }
    }, 5000);

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
      window.removeEventListener('nixis:mock-event', handleMockEvent);
      window.removeEventListener('nixis:reconnect', handleReconnect);
    };
  }, [appendEvent, updateLabel, recordLatency, recordEvent, setConnectionState, updateLastSequence, setBundleStatus]);

  const handleStartDemo = useCallback(() => {
    if (!import.meta.env.DEV) return;
    useGovernanceStore.getState().clear?.();

    const apiBase = getDaemonApiBase();
    import('./mocks/demoScenario').then(({ runLiveDemoScenario }) => {
      // Do NOT replace real daemon policies with getDemoPolicies() — allPolicies.ts is a stub
      // that returns [] so getDemoPolicies() only has 6 core entries. The daemon already
      // loaded the full policy set via loadPolicies() at startup; keep it.
      fetch(`${apiBase}/healthz`, { signal: AbortSignal.timeout(1000) })
        .then(() => {
          // Daemon is reachable — use live evaluation
          mockGenRef.current?.stop();
          mockGenRef.current = null;
          const cancel = runLiveDemoScenario(apiBase, (err) => console.error('demo error:', err));
          mockGenRef.current = { stop: cancel };
        })
        .catch(() => {
          // Daemon not reachable — fall back to offline mock
          console.warn('nixis-daemon not reachable — running offline demo');
          useStreamStore.getState().setConnectionState('MOCK');
          useStreamStore.getState().setRequestMockMode(false);
          setTimeout(() => useStreamStore.getState().setRequestMockMode(true), 100);
        });
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
      {connectionState === 'ERROR' && (
        <div
          role="alert"
          aria-live="assertive"
          style={{
            position: 'fixed', top: 0, left: 0, right: 0, zIndex: 9999,
            background: '#cf222e', color: '#fff',
            padding: '10px 20px', textAlign: 'center',
            fontWeight: 700, fontSize: 14, letterSpacing: '0.01em',
          }}
        >
          Daemon unreachable — governance is NOT being enforced. Start the Nixis daemon.
        </div>
      )}
      <CommandPalette />

      {/* Playground drawer — slides in from top-right */}
      {playgroundOpen && (
        <div
          onClick={() => setPlaygroundOpen(false)}
          style={{
            position: 'fixed', inset: 0, zIndex: 200,
            background: 'rgba(0,0,0,0.4)',
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              position: 'absolute', top: 44, right: 0,
              width: 560, maxHeight: 'calc(100vh - 44px)',
              background: 'var(--bg-surface)',
              borderLeft: '1px solid var(--border)',
              borderBottom: '1px solid var(--border)',
              overflow: 'auto',
              boxShadow: '-8px 0 24px rgba(0,0,0,0.4)',
            }}
          >
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '10px 16px', borderBottom: '1px solid var(--border)',
              background: 'var(--bg-base)',
            }}>
              <span style={{ fontSize: 12, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>
                ⚡ Policy Playground
              </span>
              <button
                onClick={() => setPlaygroundOpen(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-secondary)', fontSize: 16, lineHeight: 1, padding: '2px 4px' }}
              >
                ✕
              </button>
            </div>
            <div style={{ padding: 16 }}>
              <PolicyPlayground />
            </div>
          </div>
        </div>
      )}

      <AppShell
        header={
          <AppHeader
            connectionState={connectionState}
            onStartDemo={handleStartDemo}
            onStopDemo={handleStopDemo}
            onOpenPalette={() => useUIStore.getState().setCommandPaletteOpen(true)}
            onOpenPlayground={() => setPlaygroundOpen(true)}
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
