import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createEventBus, RingBuffer } from './event-bus';
import type { ValidatedEvent } from './ingestion-pipeline';

function makeEvent(seq: number, type: ValidatedEvent['type'] = 'policy.evaluated'): ValidatedEvent {
  const base = {
    envelope: { type, id: `evt-${seq}`, aegissequence: seq, data: {} },
  };
  if (type === 'policy.evaluated') {
    return {
      ...base,
      type: 'policy.evaluated',
      data: {
        tool: 'Shell',
        session_id: 'sess-1',
        decision: { action: 'allow', reason: '', policy_id: 'p', enforcing_layer: 'adapter', labels: { confidentiality: 0, integrity: 0, categories: 0 } },
        label_state: 'fresh',
        latency_ns: 0,
      },
    } as ValidatedEvent;
  }
  return {
    ...base,
    type: 'stream.heartbeat',
    data: { serverTime: Date.now() },
  } as ValidatedEvent;
}

describe('RingBuffer', () => {
  it('stores pushed items and reads them back', () => {
    const rb = new RingBuffer<number>(5);
    rb.push(1); rb.push(2); rb.push(3);
    expect(rb.read(0, 3)).toEqual([1, 2, 3]);
    expect(rb.size).toBe(3);
  });

  it('evicts oldest item when full — TestEventBus_RingBufferEviction', () => {
    const rb = new RingBuffer<number>(3);
    rb.push(1); rb.push(2); rb.push(3);
    rb.push(4); // evicts 1
    expect(rb.size).toBe(3);
    expect(rb.read(0, 3)).toEqual([2, 3, 4]);
  });

  it('read with out-of-range indices returns empty array', () => {
    const rb = new RingBuffer<number>(5);
    rb.push(1);
    expect(rb.read(5, 10)).toEqual([]);
    expect(rb.read(0, 0)).toEqual([]);
  });

  it('capacity 10,000 — 10,001 pushes evict oldest', () => {
    const rb = new RingBuffer<number>(10_000);
    expect(rb.capacity).toBe(10_000);
    for (let i = 0; i <= 10_000; i++) rb.push(i);
    expect(rb.size).toBe(10_000);
    const items = rb.read(0, 10_000);
    expect(items[0]).toBe(1);         // 0 was evicted
    expect(items[9999]).toBe(10_000); // newest
  });
});

describe('createEventBus', () => {
  beforeEach(() => {
    // The stub fires synchronously. Returning null (not 0) ensures rafId stays
    // null after the callback completes, so subsequent emits can schedule fresh frames.
    vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => {
      cb(performance.now());
      return null as unknown as number;
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('delivers events to a subscriber — TestEventBus_FanOut_AllConsumers', () => {
    const bus = createEventBus();
    const received: ValidatedEvent[] = [];
    bus.subscribe(() => true, (evts: ValidatedEvent[]) => received.push(...evts));
    bus.emit(makeEvent(1));
    expect(received).toHaveLength(1);
  });

  it('delivers one event to all subscribers', () => {
    const bus = createEventBus();
    const a: ValidatedEvent[] = [];
    const b: ValidatedEvent[] = [];
    bus.subscribe(() => true, (evts: ValidatedEvent[]) => a.push(...evts));
    bus.subscribe(() => true, (evts: ValidatedEvent[]) => b.push(...evts));
    bus.emit(makeEvent(1));
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
  });

  it('filter restricts events per subscriber', () => {
    const bus = createEventBus();
    const denials: ValidatedEvent[] = [];
    const all: ValidatedEvent[] = [];
    bus.subscribe((e: ValidatedEvent) => e.type === 'policy.denied', (evts: ValidatedEvent[]) => denials.push(...evts));
    bus.subscribe(() => true, (evts: ValidatedEvent[]) => all.push(...evts));
    bus.emit(makeEvent(1, 'policy.evaluated'));
    bus.emit(makeEvent(2, 'stream.heartbeat'));
    expect(denials).toHaveLength(0);
    expect(all).toHaveLength(2);
  });

  it('dispatches subscribers in priority order (lower = higher priority)', () => {
    const bus = createEventBus();
    const order: string[] = [];
    bus.subscribe(() => true, () => order.push('low'), 10);
    bus.subscribe(() => true, () => order.push('high'), 1);
    bus.emit(makeEvent(1));
    expect(order).toEqual(['high', 'low']);
  });

  it('unsubscribe stops delivery', () => {
    const bus = createEventBus();
    const received: ValidatedEvent[] = [];
    const unsub = bus.subscribe(() => true, (evts: ValidatedEvent[]) => received.push(...evts));
    bus.emit(makeEvent(1));
    unsub();
    bus.emit(makeEvent(2));
    expect(received).toHaveLength(1);
  });

  it('getBufferUtilization returns 0 for empty buffer', () => {
    expect(createEventBus().getBufferUtilization()).toBe(0);
  });

  it('getBufferUtilization increases as events are emitted', () => {
    const bus = createEventBus();
    bus.subscribe(() => true, () => {});
    for (let i = 0; i < 100; i++) bus.emit(makeEvent(i));
    expect(bus.getBufferUtilization()).toBeGreaterThan(0);
  });
});
