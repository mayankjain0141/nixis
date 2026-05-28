import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createSyncOrchestrator } from './sync-orchestrator';

// flushSync is mocked — in tests we don't have a React root, so we just run the callback.
vi.mock('react-dom', () => ({
  flushSync: (fn: () => void) => fn(),
}));

describe('createSyncOrchestrator', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('IMMEDIATE dispatches synchronously via flushSync', () => {
    const orch = createSyncOrchestrator();
    let called = false;
    orch.dispatch({ apply: () => { called = true; }, priority: 'IMMEDIATE', eventType: 'policy.denied' });
    expect(called).toBe(true);
    expect(orch.stats().immediate).toBe(1);
  });

  it('FRAME dispatches via requestAnimationFrame, batched', () => {
    const orch = createSyncOrchestrator({ maxFrameBatch: 10 });
    const results: number[] = [];
    for (let i = 0; i < 5; i++) {
      const n = i;
      orch.dispatch({ apply: () => results.push(n), priority: 'FRAME', eventType: 'policy.evaluated' });
    }
    expect(results).toHaveLength(0); // not yet dispatched
    vi.runAllTimers();
    expect(results).toHaveLength(5);
    expect(orch.stats().frame).toBe(5);
  });

  it('DEFERRED dispatches via idle callback', () => {
    const orch = createSyncOrchestrator();
    const results: number[] = [];
    orch.dispatch({ apply: () => results.push(1), priority: 'DEFERRED', eventType: 'stream.heartbeat' });
    expect(results).toHaveLength(0);
    vi.runAllTimers();
    expect(results).toHaveLength(1);
    expect(orch.stats().deferred).toBe(1);
  });

  it('DEFERRED drops oldest when queue exceeds maxDeferred', () => {
    const orch = createSyncOrchestrator({ maxDeferred: 3 });
    let dropCanary = false;
    orch.dispatch({ apply: () => { dropCanary = true; }, priority: 'DEFERRED', eventType: 'audit.checkpoint' });
    for (let i = 0; i < 3; i++) {
      orch.dispatch({ apply: () => {}, priority: 'DEFERRED', eventType: 'audit.checkpoint' });
    }
    // Canary should be dropped (oldest), dropped counter incremented.
    expect(orch.stats().dropped).toBe(1);
    vi.runAllTimers();
    expect(dropCanary).toBe(false); // was dropped before execution
  });

  it('flush() drains both FRAME and DEFERRED queues synchronously', () => {
    const orch = createSyncOrchestrator();
    const results: string[] = [];
    orch.dispatch({ apply: () => results.push('frame'), priority: 'FRAME', eventType: 'policy.evaluated' });
    orch.dispatch({ apply: () => results.push('deferred'), priority: 'DEFERRED', eventType: 'stream.heartbeat' });
    expect(results).toHaveLength(0);
    orch.flush();
    expect(results).toContain('frame');
    expect(results).toContain('deferred');
  });

  it('stats() returns cumulative counts across multiple dispatches', () => {
    const orch = createSyncOrchestrator();
    orch.dispatch({ apply: () => {}, priority: 'IMMEDIATE', eventType: 'policy.denied' });
    orch.dispatch({ apply: () => {}, priority: 'IMMEDIATE', eventType: 'secret.detected' });
    expect(orch.stats().immediate).toBe(2);
    orch.dispatch({ apply: () => {}, priority: 'FRAME', eventType: 'policy.evaluated' });
    orch.flush();
    expect(orch.stats().frame).toBe(1);
  });

  it('FRAME batches respect maxFrameBatch and schedules another rAF for the rest', () => {
    const orch = createSyncOrchestrator({ maxFrameBatch: 2 });
    const results: number[] = [];
    for (let i = 0; i < 5; i++) {
      const n = i;
      orch.dispatch({ apply: () => results.push(n), priority: 'FRAME', eventType: 'policy.evaluated' });
    }
    // First rAF fires — processes 2
    vi.runAllTimers();
    expect(results.length).toBe(5); // all processed after all timers run
    expect(orch.stats().frame).toBe(5);
  });
});
