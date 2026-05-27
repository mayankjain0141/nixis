// WS-18: Event Bus
// Ring buffer (cap=10,000) + rAF-aligned fan-out to prioritised consumers.
// Never grows beyond capacity — evicts oldest on full (FIFO).

import type { ValidatedEvent } from './ingestion-pipeline';

export type EventFilter = (event: ValidatedEvent) => boolean;
export type EventConsumer = (events: ValidatedEvent[]) => void;

export interface IEventBus {
  emit(event: ValidatedEvent): void;
  subscribe(filter: EventFilter, handler: EventConsumer, priority?: number): () => void;
  getBufferUtilization(): number;
}

export interface IRingBuffer<T> {
  push(item: T): void;
  read(from: number, to: number): T[];
  readonly size: number;
  readonly capacity: number;
}

// ── Ring buffer ───────────────────────────────────────────────────────────────
// Fixed-size circular array. head = next write slot. When full, the push
// advances head past the oldest entry — O(1) push, O(n) range read.
// Does not use `implements` (erasableSyntaxOnly forbids it); structurally compatible.

export class RingBuffer<T> {
  private readonly items: (T | undefined)[];
  private head = 0;
  private count = 0;
  readonly capacity: number;

  constructor(cap: number) {
    this.capacity = cap;
    this.items = new Array<T | undefined>(cap).fill(undefined);
  }

  push(item: T): void {
    this.items[this.head] = item;
    this.head = (this.head + 1) % this.capacity;
    if (this.count < this.capacity) this.count++;
    // When count === capacity, head wrapped past the oldest — FIFO eviction.
  }

  // read returns items at logical indices [from, to) relative to the oldest entry.
  read(from: number, to: number): T[] {
    const lo = Math.max(0, from);
    const hi = Math.min(this.count, to);
    if (lo >= hi) return [];
    const oldest = (this.head - this.count + this.capacity * 2) % this.capacity;
    const result: T[] = [];
    for (let i = lo; i < hi; i++) {
      const item = this.items[(oldest + i) % this.capacity];
      if (item !== undefined) result.push(item);
    }
    return result;
  }

  get size(): number { return this.count; }
}

// ── Subscriber ────────────────────────────────────────────────────────────────

interface Subscriber {
  filter: EventFilter;
  handler: EventConsumer;
  priority: number;
}

// ── Event Bus ─────────────────────────────────────────────────────────────────

const RING_BUFFER_CAPACITY = 10_000;

export function createEventBus(): IEventBus {
  const buffer = new RingBuffer<ValidatedEvent>(RING_BUFFER_CAPACITY);
  const subscribers: Subscriber[] = [];
  let pending: ValidatedEvent[] = [];
  let rafId: ReturnType<typeof requestAnimationFrame> | null = null;

  function scheduleDispatch(): void {
    if (rafId !== null) return;
    rafId = requestAnimationFrame(() => {
      rafId = null;
      const batch = pending;
      pending = [];
      if (batch.length === 0) return;
      const sorted = [...subscribers].sort((a, b) => a.priority - b.priority);
      for (const sub of sorted) {
        const matching = batch.filter(sub.filter);
        if (matching.length > 0) sub.handler(matching);
      }
    });
  }

  return {
    emit(event) {
      buffer.push(event);
      pending.push(event);
      scheduleDispatch();
    },

    subscribe(filter, handler, priority = 5) {
      const sub: Subscriber = { filter, handler, priority };
      subscribers.push(sub);
      return () => { const i = subscribers.indexOf(sub); if (i >= 0) subscribers.splice(i, 1); };
    },

    getBufferUtilization() {
      return buffer.size / RING_BUFFER_CAPACITY;
    },
  };
}
