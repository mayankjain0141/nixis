import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createSyncOrchestrator, atomicUpdate } from './sync-orchestrator';
import type { ProcessedBatch } from './backpressure';
import type { ValidatedEvent } from './ingestion-pipeline';

// flushSync is mocked — in tests we don't have a React root, so we just run the callback.
vi.mock('react-dom', () => ({
  flushSync: (fn: () => void) => fn(),
}));

// ── Fixture helpers ───────────────────────────────────────────────────────────

function makeDeniedEvent(seq = 1): ValidatedEvent {
  return {
    type: 'policy.denied',
    envelope: { type: 'policy.denied', nixissequence: seq, id: `evt-${seq}` },
    data: {
      tool: 'Shell',
      session_id: 'sess-1',
      decision: {
        action: 'deny',
        reason: 'Blocked',
        policy_id: 'pol-1',
        enforcing_layer: 'cel',
        labels: { confidentiality: 0, integrity: 0, categories: 0 },
      },
      label_state: 'fresh',
      latency_ns: 1000,
    },
  };
}

function makeAllowedEvent(seq = 1): ValidatedEvent {
  return {
    type: 'policy.evaluated',
    envelope: { type: 'policy.evaluated', nixissequence: seq, id: `evt-${seq}` },
    data: {
      tool: 'Read',
      session_id: 'sess-1',
      decision: {
        action: 'allow',
        reason: '',
        policy_id: 'pol-1',
        enforcing_layer: 'adapter',
        labels: { confidentiality: 0, integrity: 0, categories: 0 },
      },
      label_state: 'fresh',
      latency_ns: 500,
    },
  };
}

function makeProcessedBatch(immediateEvents: ValidatedEvent[]): ProcessedBatch {
  return {
    immediateEvents,
    coalescedSummary: [],
    frameStats: { queueDepth: 0, pressure: 'NORMAL', droppedLow: 0 },
  };
}

// ── WS-21 Acceptance Criteria ─────────────────────────────────────────────────

// TestSync_AtomicCrossStore: governance event → both governance-store and metrics-store updated in same tick
describe('TestSync_AtomicCrossStore', () => {
  it('atomicUpdate applies all mutations in a single apply() call', () => {
    const orch = createSyncOrchestrator();
    const calls: string[] = [];
    const update = atomicUpdate('FRAME', 'policy.evaluated',
      () => calls.push('governance'),
      () => calls.push('metrics'),
    );
    // Both mutations must execute inside one apply
    let applyCount = 0;
    const origApply = update.apply;
    update.apply = () => { applyCount++; origApply(); };
    orch.dispatchUpdate(update);
    // Flush to execute
    orch.flush();
    expect(applyCount).toBe(1);
    expect(calls).toEqual(['governance', 'metrics']);
  });

  it('multiple mutations in atomicUpdate execute in order', () => {
    const orch = createSyncOrchestrator();
    const order: number[] = [];
    const update = atomicUpdate('FRAME', 'policy.evaluated',
      () => order.push(1),
      () => order.push(2),
      () => order.push(3),
    );
    orch.dispatchUpdate(update);
    orch.flush();
    expect(order).toEqual([1, 2, 3]);
  });
});

// TestSync_CriticalImmediate: DENY event → store updated within same React render cycle (flushSync)
describe('TestSync_CriticalImmediate', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('IMMEDIATE priority dispatches synchronously without needing flush', () => {
    const orch = createSyncOrchestrator();
    let called = false;
    orch.dispatchUpdate({ apply: () => { called = true; }, priority: 'IMMEDIATE', eventType: 'policy.denied' });
    // No flush needed — must already be called
    expect(called).toBe(true);
    expect(orch.stats().immediate).toBe(1);
  });

  it('dispatch(batch) records immediate events from ProcessedBatch', () => {
    const orch = createSyncOrchestrator();
    const batch = makeProcessedBatch([makeDeniedEvent(1), makeDeniedEvent(2)]);
    orch.dispatch(batch);
    // dispatch records the immediateEvents count
    expect(orch.stats().immediate).toBe(2);
  });

  it('DENY event update dispatched as IMMEDIATE executes before FRAME events', () => {
    const orch = createSyncOrchestrator();
    const order: string[] = [];
    orch.dispatchUpdate(atomicUpdate('FRAME', 'policy.evaluated', () => order.push('frame')));
    orch.dispatchUpdate(atomicUpdate('IMMEDIATE', 'policy.denied', () => order.push('immediate')));
    // IMMEDIATE should already be called; flush drains FRAME
    orch.flush();
    expect(order[0]).toBe('immediate');
    expect(order[1]).toBe('frame');
  });
});

// ── Additional interface compliance tests ─────────────────────────────────────

describe('createSyncOrchestrator', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('FRAME dispatches via requestAnimationFrame, not synchronously', () => {
    const orch = createSyncOrchestrator({ maxFrameBatch: 10 });
    const results: number[] = [];
    for (let i = 0; i < 5; i++) {
      const n = i;
      orch.dispatchUpdate({ apply: () => results.push(n), priority: 'FRAME', eventType: 'policy.evaluated' });
    }
    expect(results).toHaveLength(0);
    vi.runAllTimers();
    expect(results).toHaveLength(5);
    expect(orch.stats().frame).toBe(5);
  });

  it('DEFERRED dispatches via idle callback', () => {
    const orch = createSyncOrchestrator();
    const results: number[] = [];
    orch.dispatchUpdate({ apply: () => results.push(1), priority: 'DEFERRED', eventType: 'stream.heartbeat' });
    expect(results).toHaveLength(0);
    vi.runAllTimers();
    expect(results).toHaveLength(1);
    expect(orch.stats().deferred).toBe(1);
  });

  it('DEFERRED drops oldest when queue exceeds maxDeferred', () => {
    const orch = createSyncOrchestrator({ maxDeferred: 3 });
    let dropCanary = false;
    orch.dispatchUpdate({ apply: () => { dropCanary = true; }, priority: 'DEFERRED', eventType: 'audit.checkpoint' });
    for (let i = 0; i < 3; i++) {
      orch.dispatchUpdate({ apply: () => {}, priority: 'DEFERRED', eventType: 'audit.checkpoint' });
    }
    expect(orch.stats().dropped).toBe(1);
    vi.runAllTimers();
    expect(dropCanary).toBe(false);
  });

  it('flush() drains both FRAME and DEFERRED queues synchronously', () => {
    const orch = createSyncOrchestrator();
    const results: string[] = [];
    orch.dispatchUpdate({ apply: () => results.push('frame'), priority: 'FRAME', eventType: 'policy.evaluated' });
    orch.dispatchUpdate({ apply: () => results.push('deferred'), priority: 'DEFERRED', eventType: 'stream.heartbeat' });
    expect(results).toHaveLength(0);
    orch.flush();
    expect(results).toContain('frame');
    expect(results).toContain('deferred');
  });

  it('stats() returns cumulative counts across multiple dispatches', () => {
    const orch = createSyncOrchestrator();
    orch.dispatchUpdate({ apply: () => {}, priority: 'IMMEDIATE', eventType: 'policy.denied' });
    orch.dispatchUpdate({ apply: () => {}, priority: 'IMMEDIATE', eventType: 'secret.detected' });
    expect(orch.stats().immediate).toBe(2);
    orch.dispatchUpdate({ apply: () => {}, priority: 'FRAME', eventType: 'policy.evaluated' });
    orch.flush();
    expect(orch.stats().frame).toBe(1);
  });

  it('FRAME respects maxFrameBatch and schedules another rAF for remainder', () => {
    const orch = createSyncOrchestrator({ maxFrameBatch: 2 });
    const results: number[] = [];
    for (let i = 0; i < 5; i++) {
      const n = i;
      orch.dispatchUpdate({ apply: () => results.push(n), priority: 'FRAME', eventType: 'policy.evaluated' });
    }
    vi.runAllTimers();
    expect(results.length).toBe(5);
    expect(orch.stats().frame).toBe(5);
  });

  it('onEvent hook receives each event with its event-type priority', () => {
    const received: Array<{ type: string; priority: string }> = [];
    const orch = createSyncOrchestrator({
      onEvent: (ev, priority) => received.push({ type: ev.type, priority }),
    });
    // policy.denied → IMMEDIATE; policy.evaluated → FRAME per eventPriority()
    const batch = makeProcessedBatch([makeDeniedEvent(1), makeAllowedEvent(2)]);
    orch.dispatch(batch);
    expect(received).toHaveLength(2);
    expect(received.find(r => r.type === 'policy.denied')?.priority).toBe('IMMEDIATE');
    expect(received.find(r => r.type === 'policy.evaluated')?.priority).toBe('FRAME');
  });
});
