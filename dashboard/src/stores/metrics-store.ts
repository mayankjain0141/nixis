import { create } from 'zustand';
import { immer } from 'zustand/middleware/immer';

export interface LatencyBucket {
  p50: number;
  p95: number;
  p99: number;
  maxNs: number;
  sampleCount: number;
}

const MAX_LATENCY_SAMPLES = 1000;
const MAX_RATE_WINDOW = 60; // seconds of per-second buckets

// computeBucket is O(n log n) — only called on explicit read, never on every write.
function computeBucket(samples: readonly number[]): LatencyBucket {
  if (samples.length === 0) {
    return { p50: 0, p95: 0, p99: 0, maxNs: 0, sampleCount: 0 };
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const p = (pct: number) => sorted[Math.floor(sorted.length * pct)] ?? 0;
  return {
    p50: p(0.5),
    p95: p(0.95),
    p99: p(0.99),
    maxNs: sorted[sorted.length - 1],
    sampleCount: sorted.length,
  };
}

interface MetricsState {
  latencySamples: number[];
  // Events per second, keyed by unix second.
  rateWindow: Map<number, number>;
  totalEventsProcessed: number;

  recordLatency(latencyNs: number): void;
  recordEvent(timestampMs: number): void;
  // Computed on demand — O(n log n); do not call on the hot render path.
  getLatencyBucket(): LatencyBucket;
  getEventsPerSecond(): number;
}

export const useMetricsStore = create<MetricsState>()(
  immer((set, get) => ({
    latencySamples: [],
    rateWindow: new Map(),
    totalEventsProcessed: 0,

    recordLatency(latencyNs) {
      set((draft) => {
        draft.latencySamples.push(latencyNs);
        if (draft.latencySamples.length > MAX_LATENCY_SAMPLES) {
          draft.latencySamples.splice(0, draft.latencySamples.length - MAX_LATENCY_SAMPLES);
        }
        draft.totalEventsProcessed++;
      });
    },

    recordEvent(timestampMs) {
      set((draft) => {
        const sec = Math.floor(timestampMs / 1000);
        draft.rateWindow.set(sec, (draft.rateWindow.get(sec) ?? 0) + 1);
        const cutoff = sec - MAX_RATE_WINDOW;
        for (const key of draft.rateWindow.keys()) {
          if (key < cutoff) draft.rateWindow.delete(key);
        }
      });
    },

    getLatencyBucket() {
      return computeBucket(get().latencySamples);
    },

    getEventsPerSecond() {
      const now = Math.floor(Date.now() / 1000);
      const { rateWindow } = get();
      let total = 0;
      for (let s = now - 5; s <= now; s++) {
        total += rateWindow.get(s) ?? 0;
      }
      return total / 6;
    },
  })),
);
