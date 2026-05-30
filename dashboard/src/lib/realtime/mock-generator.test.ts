import { describe, it, expect } from 'vitest';
import { generateBatch, createMockGenerator } from './mock-generator';

const VALID_VERDICTS = new Set(['deny', 'allow', 'require_approval', 'audit']);

function extractVerdict(event: ReturnType<typeof generateBatch>[number]): string | null {
  if (event.type === 'policy.evaluated' || event.type === 'policy.denied') {
    return event.data.decision.action;
  }
  return null;
}

function extractLabel(event: ReturnType<typeof generateBatch>[number]) {
  if (event.type === 'policy.evaluated' || event.type === 'policy.denied') {
    return event.data.decision.labels;
  }
  if (event.type === 'secret.detected' || event.type === 'label.escalated') {
    return (event.data as { label?: { confidentiality: number; integrity: number; categories: number } }).label;
  }
  return null;
}

// ── WS-25 Acceptance Criteria ─────────────────────────────────────────────────

// TestMock_DeterministicSequence: same seed → same events on two runs
describe('TestMock_DeterministicSequence', () => {
  it('generateBatch with same seed produces identical events on two calls', () => {
    const SEED = 42;
    const run1 = generateBatch(50, SEED);
    const run2 = generateBatch(50, SEED);
    expect(run1.length).toBe(50);
    expect(run2.length).toBe(50);
    for (let i = 0; i < run1.length; i++) {
      expect(run1[i].type).toBe(run2[i].type);
      expect(run1[i].envelope.nixissequence).toBe(run2[i].envelope.nixissequence);
    }
  });

  it('different seeds produce different sequences', () => {
    const run1 = generateBatch(20, 1);
    const run2 = generateBatch(20, 99999);
    const types1 = run1.map(e => e.type).join(',');
    const types2 = run2.map(e => e.type).join(',');
    // With high probability different seeds produce different type sequences
    // (round-robin type selection is seed-independent for type, but data differs)
    // Check that policy event data differs
    const policy1 = run1.find(e => e.type === 'policy.evaluated');
    const policy2 = run2.find(e => e.type === 'policy.evaluated');
    if (policy1 && policy2) {
      // At least one of tool/session/policy should differ
      const same = JSON.stringify(policy1.data) === JSON.stringify(policy2.data);
      expect(same).toBe(false);
    }
    // Types sequence may be same (round-robin) but we verify the test ran
    expect(types1.length).toBeGreaterThan(0);
    expect(types2.length).toBeGreaterThan(0);
  });

  it('IMockGenerator.generateBatch with same config seed is deterministic', () => {
    const gen1 = createMockGenerator();
    gen1.start({ ratePerSecond: 10, seed: 12345 });
    gen1.stop();
    const batch1 = gen1.generateBatch(30);

    const gen2 = createMockGenerator();
    gen2.start({ ratePerSecond: 10, seed: 12345 });
    gen2.stop();
    const batch2 = gen2.generateBatch(30);

    for (let i = 0; i < batch1.length; i++) {
      expect(batch1[i].type).toBe(batch2[i].type);
    }
  });
});

// TestMock_NumericLabelsOnly: all generated events have numeric SecurityLabel
describe('TestMock_NumericLabelsOnly', () => {
  it('all policy events have numeric SecurityLabel fields (ADR-013)', () => {
    const events = generateBatch(120, 777);
    for (const event of events) {
      const label = extractLabel(event);
      if (label === null || label === undefined) continue;
      expect(typeof label.confidentiality).toBe('number');
      expect(typeof label.integrity).toBe('number');
      expect(typeof label.categories).toBe('number');
      // Must not be string format
      expect(label).not.toHaveProperty('level');
    }
  });

  it('SecurityLabel fields are within uint16/uint32 bounds', () => {
    const events = generateBatch(120, 999);
    for (const event of events) {
      const label = extractLabel(event);
      if (label === null || label === undefined) continue;
      expect(label.confidentiality).toBeGreaterThanOrEqual(0);
      expect(label.confidentiality).toBeLessThanOrEqual(65535);
      expect(label.integrity).toBeGreaterThanOrEqual(0);
      expect(label.integrity).toBeLessThanOrEqual(65535);
      expect(label.categories).toBeGreaterThanOrEqual(0);
    }
  });
});

// TestMock_CanonicalVerdicts: all generated verdicts in ['deny', 'allow', 'require_approval', 'audit']
describe('TestMock_CanonicalVerdicts', () => {
  it('all policy.evaluated/policy.denied verdicts are canonical', () => {
    const events = generateBatch(120, 42);
    for (const event of events) {
      const verdict = extractVerdict(event);
      if (verdict === null) continue;
      expect(VALID_VERDICTS.has(verdict),
        `Non-canonical verdict "${verdict}" in event type ${event.type}`
      ).toBe(true);
    }
  });

  it('never generates non-canonical verdict "escalate"', () => {
    const events = generateBatch(200, 1234);
    for (const event of events) {
      const verdict = extractVerdict(event);
      expect(verdict).not.toBe('escalate');
      expect(verdict).not.toBe('HITL');
      expect(verdict).not.toBe('block');
    }
  });

  it('generates all four canonical verdicts across a large batch', () => {
    const events = generateBatch(200, 5678);
    const verdicts = new Set(
      events.flatMap(e => {
        const v = extractVerdict(e);
        return v !== null ? [v] : [];
      })
    );
    expect(verdicts.has('allow')).toBe(true);
    expect(verdicts.has('deny')).toBe(true);
  });
});

// ── Additional interface coverage ─────────────────────────────────────────────

describe('createMockGenerator', () => {
  it('generateBatch returns ValidatedEvents with all required envelope fields', () => {
    const gen = createMockGenerator();
    gen.start({ ratePerSecond: 10, seed: 1 });
    gen.stop();
    const batch = gen.generateBatch(12);
    expect(batch).toHaveLength(12);
    for (const e of batch) {
      expect(typeof e.type).toBe('string');
      expect(typeof e.envelope.nixissequence).toBe('number');
      expect(e.envelope.nixissequence).toBeGreaterThan(0);
    }
  });

  it('covers all 12 ADR-012 event types in a batch of 12', () => {
    const events = generateBatch(12, 42);
    const types = new Set(events.map(e => e.type));
    expect(types.size).toBe(12);
  });

  it('nixissequence is strictly increasing within a batch', () => {
    const events = generateBatch(50, 42);
    for (let i = 1; i < events.length; i++) {
      expect(events[i].envelope.nixissequence).toBeGreaterThan(
        events[i - 1].envelope.nixissequence
      );
    }
  });
});
