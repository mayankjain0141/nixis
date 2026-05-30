import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createStreamProcessor, OrderedEventList } from './stream-processor';
import type { ValidatedEvent } from './ingestion-pipeline';

// ── Fixture helpers ───────────────────────────────────────────────────────────

function makePolicyEvaluated(
  seq: number,
  action: 'allow' | 'deny' | 'require_approval' | 'audit' = 'allow',
  tool = 'Shell',
  latencyNs = 1_000_000,
  sessionId = 'sess-1',
): ValidatedEvent {
  return {
    type: 'policy.evaluated',
    envelope: {
      type: 'policy.evaluated',
      nixissequence: seq,
      id: `evt-${seq}`,
      time: new Date().toISOString(),
    },
    data: {
      tool,
      session_id: sessionId,
      decision: {
        action,
        reason: '',
        policy_id: 'pol-1',
        enforcing_layer: 'adapter',
        labels: { confidentiality: 0, integrity: 0, categories: 0 },
      },
      label_state: 'fresh',
      latency_ns: latencyNs,
    },
  };
}

function makePolicyDenied(seq: number, tool = 'GitPush', latencyNs = 2_000_000): ValidatedEvent {
  return {
    type: 'policy.denied',
    envelope: { type: 'policy.denied', nixissequence: seq, id: `evt-${seq}` },
    data: {
      tool,
      session_id: 'sess-2',
      decision: {
        action: 'deny',
        reason: 'Force push blocked',
        policy_id: 'pol-2',
        enforcing_layer: 'cel',
        labels: { confidentiality: 0, integrity: 0, categories: 0 },
      },
      label_state: 'fresh',
      latency_ns: latencyNs,
    },
  };
}

// ── OrderedEventList tests ────────────────────────────────────────────────────

describe('OrderedEventList', () => {
  it('maintains ascending nixissequence order on insertion', () => {
    const list = new OrderedEventList();
    list.insert(makePolicyEvaluated(3));
    list.insert(makePolicyEvaluated(1));
    list.insert(makePolicyEvaluated(2));
    const seqs = list.toArray().map(e => e.envelope.nixissequence);
    expect(seqs).toEqual([1, 2, 3]);
  });

  it('drops duplicate nixissequence silently', () => {
    const list = new OrderedEventList();
    list.insert(makePolicyEvaluated(1));
    list.insert(makePolicyEvaluated(1));
    expect(list.length).toBe(1);
  });

  it('handles already-ordered insertion', () => {
    const list = new OrderedEventList();
    for (let i = 1; i <= 5; i++) list.insert(makePolicyEvaluated(i));
    const seqs = list.toArray().map(e => e.envelope.nixissequence);
    expect(seqs).toEqual([1, 2, 3, 4, 5]);
  });
});

// ── WS-20 Acceptance Criteria ─────────────────────────────────────────────────

// TestStream_AuditOrdering
describe('TestStream_AuditOrdering', () => {
  it('events arriving out of order are stored in sequence order in the audit trail', () => {
    const sp = createStreamProcessor();
    sp.processBatch([
      makePolicyEvaluated(3),
      makePolicyEvaluated(1),
      makePolicyEvaluated(2),
    ]);
    const ordered = sp.getOrderedEvents();
    const seqs = ordered.map(e => e.envelope.nixissequence);
    expect(seqs).toEqual([1, 2, 3]);
  });

  it('interleaved batches maintain strict order', () => {
    const sp = createStreamProcessor();
    sp.processBatch([makePolicyEvaluated(5), makePolicyEvaluated(2)]);
    sp.processBatch([makePolicyEvaluated(1), makePolicyEvaluated(4), makePolicyEvaluated(3)]);
    const seqs = sp.getOrderedEvents().map(e => e.envelope.nixissequence);
    expect(seqs).toEqual([1, 2, 3, 4, 5]);
  });
});

// TestStream_WindowedAggregation
describe('TestStream_WindowedAggregation', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('30s window counts only events within the last 30 seconds', () => {
    const sp = createStreamProcessor();
    sp.processBatch([
      makePolicyEvaluated(1, 'allow'),
      makePolicyEvaluated(2, 'deny'),
      makePolicyEvaluated(3, 'allow'),
    ]);
    vi.advanceTimersByTime(35_000);
    sp.processBatch([
      makePolicyEvaluated(4, 'audit'),
      makePolicyEvaluated(5, 'allow'),
    ]);
    const w = sp.getWindow('LAST_30S');
    expect(w.allow + w.deny + w.require_approval + w.audit).toBe(2);
    expect(w.allow).toBe(1);
    expect(w.audit).toBe(1);
    expect(w.deny).toBe(0);
  });

  it('5s window excludes events older than 5 seconds', () => {
    const sp = createStreamProcessor();
    sp.processBatch([makePolicyEvaluated(1, 'deny')]);
    vi.advanceTimersByTime(6_000);
    const w = sp.getWindow('LAST_5S');
    expect(w.allow + w.deny + w.require_approval + w.audit).toBe(0);
  });

  it('windowDurationMs matches the requested window', () => {
    const sp = createStreamProcessor();
    expect(sp.getWindow('LAST_5S').windowDurationMs).toBe(5_000);
    expect(sp.getWindow('LAST_30S').windowDurationMs).toBe(30_000);
    expect(sp.getWindow('LAST_5MIN').windowDurationMs).toBe(300_000);
    expect(sp.getWindow('LAST_1HR').windowDurationMs).toBe(3_600_000);
  });
});

// ── Additional interface compliance tests ─────────────────────────────────────

describe('createStreamProcessor', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('getMetrics returns zero state when empty', () => {
    const sp = createStreamProcessor();
    const m = sp.getMetrics();
    expect(m.verdicts.allow).toBe(0);
    expect(m.verdicts.deny).toBe(0);
    expect(m.latency.p50Ns).toBe(0);
    expect(m.throughput.totalEvents).toBe(0);
    expect(m.tools.topTools).toHaveLength(0);
  });

  it('getMetrics reflects pushed events', () => {
    const sp = createStreamProcessor();
    sp.processBatch([makePolicyEvaluated(1, 'allow'), makePolicyEvaluated(2, 'deny')]);
    const m = sp.getMetrics();
    expect(m.verdicts.allow).toBe(1);
    expect(m.verdicts.deny).toBe(1);
    expect(m.throughput.totalEvents).toBe(2);
  });

  it('onMetricsUpdate fires handler after each processBatch', () => {
    const sp = createStreamProcessor();
    const updates: number[] = [];
    sp.onMetricsUpdate(m => updates.push(m.throughput.totalEvents));
    sp.processBatch([makePolicyEvaluated(1)]);
    sp.processBatch([makePolicyEvaluated(2)]);
    expect(updates).toEqual([1, 2]);
  });

  it('onMetricsUpdate returns unsubscribe function', () => {
    const sp = createStreamProcessor();
    const updates: number[] = [];
    const unsub = sp.onMetricsUpdate(m => updates.push(m.throughput.totalEvents));
    sp.processBatch([makePolicyEvaluated(1)]);
    unsub();
    sp.processBatch([makePolicyEvaluated(2)]);
    expect(updates).toHaveLength(1);
  });

  it('setFilter restricts to specified verdicts', () => {
    const sp = createStreamProcessor();
    sp.setFilter({ verdicts: ['deny'] });
    sp.processBatch([
      makePolicyEvaluated(1, 'allow'),
      makePolicyEvaluated(2, 'deny'),
      makePolicyEvaluated(3, 'allow'),
    ]);
    const m = sp.getMetrics();
    expect(m.verdicts.deny).toBe(1);
    expect(m.verdicts.allow).toBe(0);
  });

  it('getFilters returns current filter state', () => {
    const sp = createStreamProcessor();
    sp.setFilter({ verdicts: ['deny', 'require_approval'], tools: ['Shell'] });
    const f = sp.getFilters();
    expect(f.verdicts).toEqual(['deny', 'require_approval']);
    expect(f.tools).toEqual(['Shell']);
  });

  it('getCorrelatedEvents links delegation events to policy events by session', () => {
    const sp = createStreamProcessor();
    const policyEvent = makePolicyEvaluated(1, 'allow', 'Shell', 1_000_000, 'sess-1');
    const delegEvent: ValidatedEvent = {
      type: 'delegation.created',
      envelope: { type: 'delegation.created', nixissequence: 2, id: 'del-1' },
      data: { subject: 'sess-1' },
    };
    sp.processBatch([policyEvent, delegEvent]);
    const group = sp.getCorrelatedEvents('evt-1');
    expect(group).not.toBeNull();
    expect(group?.delegationEvents).toHaveLength(1);
    expect(group?.delegationEvents[0].type).toBe('delegation.created');
  });

  it('reset clears all state', () => {
    const sp = createStreamProcessor();
    sp.processBatch([makePolicyEvaluated(1), makePolicyDenied(2)]);
    sp.reset();
    expect(sp.getMetrics().throughput.totalEvents).toBe(0);
    expect(sp.getOrderedEvents()).toHaveLength(0);
    expect(sp.getWindow('LAST_5S').allow).toBe(0);
  });

  it('denyRate includes require_approval in deny count', () => {
    const sp = createStreamProcessor();
    sp.processBatch([
      makePolicyEvaluated(1, 'allow'),
      makePolicyEvaluated(2, 'require_approval'),
    ]);
    const w = sp.getWindow('LAST_5S');
    expect(w.denyRate).toBeCloseTo(0.5);
  });

  it('latency percentiles are monotonically non-decreasing', () => {
    const sp = createStreamProcessor();
    for (let i = 1; i <= 20; i++) {
      sp.processBatch([makePolicyEvaluated(i, 'allow', 'Shell', i * 100_000)]);
    }
    const m = sp.getMetrics();
    expect(m.latency.p50Ns).toBeLessThanOrEqual(m.latency.p95Ns);
    expect(m.latency.p95Ns).toBeLessThanOrEqual(m.latency.p99Ns);
    expect(m.latency.p99Ns).toBeLessThanOrEqual(m.latency.maxNs);
  });
});
