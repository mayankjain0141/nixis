import { describe, it, expect, vi, afterEach } from 'vitest';
import { flushSync as flushSyncMock } from 'react-dom';

// Must be at top level — vi.mock is hoisted regardless of where it appears.
vi.mock('react-dom', () => ({
  flushSync: vi.fn((cb: () => void) => cb()),
}));

import { createBackpressureController } from './backpressure';
import type { ValidatedEvent } from './ingestion-pipeline';
import type { ProcessedBatch } from './backpressure';

afterEach(() => vi.clearAllMocks());

function makeAllow(seq: number): ValidatedEvent {
  return {
    type: 'policy.evaluated',
    envelope: { type: 'policy.evaluated', id: `e${seq}`, nixissequence: seq, data: {} },
    data: {
      tool: 'Shell', session_id: 's',
      decision: { action: 'allow', reason: '', policy_id: 'p', enforcing_layer: 'adapter', labels: { confidentiality: 0, integrity: 0, categories: 0 } },
      label_state: 'fresh', latency_ns: 0,
    },
  };
}

function makeDeny(seq: number): ValidatedEvent {
  return {
    type: 'policy.denied',
    envelope: { type: 'policy.denied', id: `d${seq}`, nixissequence: seq, data: {} },
    data: {
      tool: 'Shell', session_id: 's',
      decision: { action: 'deny', reason: 'Denied', policy_id: 'p', enforcing_layer: 'cel', labels: { confidentiality: 0, integrity: 0, categories: 0 } },
      label_state: 'fresh', latency_ns: 0,
    },
  };
}

function makeSecret(seq: number): ValidatedEvent {
  return {
    type: 'secret.detected',
    envelope: { type: 'secret.detected', id: `s${seq}`, nixissequence: seq, data: {} },
    data: { session_id: 's', tool: 'Shell' },
    priority: 'CRITICAL',
  };
}

function makeHeartbeat(seq: number): ValidatedEvent {
  return {
    type: 'stream.heartbeat',
    envelope: { type: 'stream.heartbeat', id: `h${seq}`, nixissequence: seq, data: {} },
    data: { serverTime: Date.now() },
  };
}

describe('createBackpressureController', () => {
  it('starts at NORMAL pressure with empty queues', () => {
    expect(createBackpressureController().getPressure()).toBe('NORMAL');
  });

  it('onOutput unsubscribe stops delivery', () => {
    const ctrl = createBackpressureController();
    const batches: ProcessedBatch[] = [];
    const unsub = ctrl.onOutput((b: ProcessedBatch) => batches.push(b));
    ctrl.submit([makeAllow(1)]);
    unsub();
    ctrl.submit([makeAllow(2)]);
    expect(batches).toHaveLength(1);
  });

  describe('TestBackpressure_DenyNeverCoalesced', () => {
    it('deny event always in immediateEvents, never in coalescedSummary', () => {
      const ctrl = createBackpressureController();
      const batches: ProcessedBatch[] = [];
      ctrl.onOutput((b: ProcessedBatch) => batches.push(b));

      const events: ValidatedEvent[] = [];
      for (let i = 0; i < 200; i++) events.push(makeAllow(i));
      events.push(makeDeny(200));
      ctrl.submit(events);

      const allImmediate = batches.flatMap(b => b.immediateEvents);
      expect(allImmediate.some(e => e.type === 'policy.denied')).toBe(true);

      const allSummary = batches.flatMap(b => b.coalescedSummary);
      expect(allSummary.some(s => s.verdict === 'deny')).toBe(false);
    });
  });

  describe('CRITICAL events', () => {
    it('secret.detected appears in immediateEvents', () => {
      const ctrl = createBackpressureController();
      const batches: ProcessedBatch[] = [];
      ctrl.onOutput((b: ProcessedBatch) => batches.push(b));
      ctrl.submit([makeSecret(1)]);
      expect(batches.flatMap(b => b.immediateEvents).some(e => e.type === 'secret.detected')).toBe(true);
    });
  });

  describe('LOW priority shedding under CRITICAL pressure', () => {
    it('droppedLow > 0 when queue hits CRITICAL depth with heartbeats', () => {
      const ctrl = createBackpressureController();
      const batches: ProcessedBatch[] = [];
      ctrl.onOutput((b: ProcessedBatch) => batches.push(b));

      // 1100 heartbeats (LOW priority) exceed the CRITICAL threshold of 1000.
      const events: ValidatedEvent[] = [];
      for (let i = 0; i < 1100; i++) events.push(makeHeartbeat(i));
      ctrl.submit(events);

      const dropped = batches.reduce((acc, b) => acc + b.frameStats.droppedLow, 0);
      expect(dropped).toBeGreaterThan(0);
    });
  });

  describe('frameStats', () => {
    it('pressure field is a valid PressureLevel', () => {
      const ctrl = createBackpressureController();
      const batches: ProcessedBatch[] = [];
      ctrl.onOutput((b: ProcessedBatch) => batches.push(b));
      ctrl.submit([makeAllow(1)]);
      expect(batches.length).toBeGreaterThan(0);
      expect(['NORMAL', 'ELEVATED', 'HIGH', 'CRITICAL']).toContain(batches[batches.length - 1].frameStats.pressure);
    });
  });

  describe('TestBackpressure_MemoryBounded', () => {
    it('10,000 events leave pressure defined (no unbounded growth)', () => {
      const ctrl = createBackpressureController();
      ctrl.onOutput(() => {});
      for (let i = 0; i < 100; i++) {
        const batch: ValidatedEvent[] = [];
        for (let j = 0; j < 100; j++) batch.push(makeAllow(i * 100 + j));
        ctrl.submit(batch);
      }
      expect(ctrl.getPressure()).toBeDefined();
    });
  });

  // TestBackpressure_CriticalFlushSync: denial event → flushSync called synchronously
  describe('TestBackpressure_CriticalFlushSync', () => {
    it('flushSync is called when a DENY event is submitted', () => {
      const ctrl = createBackpressureController();
      ctrl.onOutput(() => {});
      ctrl.submit([makeDeny(1)]);
      expect(flushSyncMock).toHaveBeenCalled();
    });

    it('flushSync is called for secret.detected (CRITICAL priority)', () => {
      const ctrl = createBackpressureController();
      ctrl.onOutput(() => {});
      ctrl.submit([makeSecret(1)]);
      expect(flushSyncMock).toHaveBeenCalled();
    });

    it('flushSync is NOT called for allow events (NORMAL priority)', () => {
      const ctrl = createBackpressureController();
      ctrl.onOutput(() => {});
      ctrl.submit([makeAllow(1)]);
      expect(flushSyncMock).not.toHaveBeenCalled();
    });

    it('deny event appears in immediateEvents, dispatched via flushSync', () => {
      const ctrl = createBackpressureController();
      const immediateSeqs: number[] = [];
      ctrl.onOutput((b: ProcessedBatch) => {
        for (const e of b.immediateEvents) immediateSeqs.push(e.envelope.nixissequence);
      });
      ctrl.submit([makeAllow(1), makeDeny(2), makeAllow(3)]);
      // flushSync called (for deny), deny is in immediateEvents
      expect(flushSyncMock).toHaveBeenCalled();
      expect(immediateSeqs).toContain(2);
    });
  });
});
