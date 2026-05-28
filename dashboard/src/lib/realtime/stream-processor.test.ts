import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createStreamProcessor, WINDOWS } from './stream-processor';
import type { ValidatedEvent } from './ingestion-pipeline';

// Minimal valid ValidatedEvent fixture for policy.evaluated.
function makePolicyEvaluated(
  seq: number,
  action: 'allow' | 'deny' | 'require_approval' | 'audit' = 'allow',
  tool = 'Shell',
  latencyNs = 1_000_000,
): ValidatedEvent {
  return {
    type: 'policy.evaluated',
    envelope: {
      type: 'policy.evaluated',
      aegissequence: seq,
      id: `evt-${seq}`,
      time: new Date().toISOString(),
    },
    data: {
      tool,
      session_id: 'sess-1',
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
    envelope: {
      type: 'policy.denied',
      aegissequence: seq,
      id: `evt-${seq}`,
    },
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

describe('createStreamProcessor', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('returns zero stats when empty', () => {
    const sp = createStreamProcessor();
    const s = sp.stats(5_000);
    expect(s.eventRate).toBe(0);
    expect(s.denyRate).toBe(0);
    expect(s.p50Ns).toBe(0);
    expect(s.topTools).toHaveLength(0);
    expect(s.windowMs).toBe(5_000);
  });

  it('push increments eventRate', () => {
    const sp = createStreamProcessor();
    sp.push(makePolicyEvaluated(1));
    sp.push(makePolicyEvaluated(2));
    sp.push(makePolicyEvaluated(3));
    const s = sp.stats(5_000);
    expect(s.eventRate).toBe(3 / 5); // 3 events / 5 seconds
  });

  it('denyRate counts deny and require_approval as denials', () => {
    const sp = createStreamProcessor();
    sp.push(makePolicyEvaluated(1, 'allow'));
    sp.push(makePolicyEvaluated(2, 'deny'));
    sp.push(makePolicyEvaluated(3, 'require_approval'));
    sp.push(makePolicyEvaluated(4, 'audit'));
    const s = sp.stats(5_000);
    expect(s.denyRate).toBeCloseTo(2 / 4);
  });

  it('policy.denied events contribute to deny distribution', () => {
    const sp = createStreamProcessor();
    sp.push(makePolicyDenied(1));
    sp.push(makePolicyDenied(2));
    const s = sp.stats(5_000);
    expect(s.distribution.deny).toBe(2);
    expect(s.denyRate).toBe(1.0);
  });

  it('topTools returns sorted by count, max 5', () => {
    const sp = createStreamProcessor();
    const tools = ['Shell', 'Read', 'Write', 'Edit', 'Bash', 'WebFetch'];
    for (let i = 0; i < 10; i++) sp.push(makePolicyEvaluated(i, 'allow', 'Shell'));
    for (const tool of tools.slice(1)) sp.push(makePolicyEvaluated(100 + tools.indexOf(tool), 'allow', tool));
    const s = sp.stats(5_000);
    expect(s.topTools).toHaveLength(5); // max 5
    expect(s.topTools[0].tool).toBe('Shell'); // most frequent first
    expect(s.topTools[0].count).toBe(10);
  });

  it('percentiles compute correctly', () => {
    const sp = createStreamProcessor();
    // Push 10 events with known latencies 1ns..10ns
    for (let i = 1; i <= 10; i++) {
      sp.push(makePolicyEvaluated(i, 'allow', 'Shell', i));
    }
    const s = sp.stats(5_000);
    expect(s.p50Ns).toBeGreaterThan(0);
    expect(s.p95Ns).toBeGreaterThanOrEqual(s.p50Ns);
    expect(s.p99Ns).toBeGreaterThanOrEqual(s.p95Ns);
  });

  it('entries outside the window are excluded', () => {
    const sp = createStreamProcessor();
    // Push one event now, then advance time past the 5s window.
    sp.push(makePolicyEvaluated(1));
    vi.advanceTimersByTime(6_000);
    const s = sp.stats(5_000);
    expect(s.eventRate).toBe(0);
  });

  it('allStats returns stats for all 4 windows', () => {
    const sp = createStreamProcessor();
    sp.push(makePolicyEvaluated(1));
    const all = sp.allStats();
    expect(all).toHaveLength(4);
    const windowIds = all.map(s => s.windowMs);
    for (const w of WINDOWS) {
      expect(windowIds).toContain(w);
    }
  });

  it('reset clears all entries', () => {
    const sp = createStreamProcessor();
    sp.push(makePolicyEvaluated(1));
    sp.push(makePolicyEvaluated(2));
    sp.reset();
    const s = sp.stats(5_000);
    expect(s.eventRate).toBe(0);
    expect(s.topTools).toHaveLength(0);
  });

  it('computedAt is approximately now', () => {
    const sp = createStreamProcessor();
    const before = Date.now();
    const s = sp.stats(5_000);
    const after = Date.now();
    expect(s.computedAt).toBeGreaterThanOrEqual(before);
    expect(s.computedAt).toBeLessThanOrEqual(after);
  });
});
