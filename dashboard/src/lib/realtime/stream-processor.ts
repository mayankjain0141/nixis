// WS-20: Stream Processor
// Circular buffer per window (5s/30s/5min/1hr). O(1) push. Stats computed on read.

import type { Action } from '../../types/aegis';
import type { ValidatedEvent } from './ingestion-pipeline';

export type WindowMs = 5_000 | 30_000 | 300_000 | 3_600_000;
export const WINDOWS: WindowMs[] = [5_000, 30_000, 300_000, 3_600_000];

export interface WindowStats {
  windowMs: WindowMs;
  eventRate: number;
  denyRate: number;
  distribution: Record<Action, number>;
  topTools: Array<{ tool: string; count: number }>;
  p50Ns: number;
  p95Ns: number;
  p99Ns: number;
  computedAt: number;
}

export interface StreamProcessor {
  push(event: ValidatedEvent & { latencyNs?: number }): void;
  stats(windowMs: WindowMs): WindowStats;
  allStats(): WindowStats[];
  reset(): void;
}

interface Entry {
  ts: number;
  action: Action;
  tool: string;
  latencyNs: number;
}

// Capacity chosen so the buffer comfortably holds data for the largest window
// even at high throughput (1000 events/sec * 3600s = 3.6M max, but we cap at 50K
// to bound memory — oldest entries fall off naturally under sustained high load).
const MAX_ENTRIES = 50_000;

function createCircularBuffer() {
  const buf = new Array<Entry | undefined>(MAX_ENTRIES).fill(undefined);
  let head = 0;
  let count = 0;

  return {
    push(entry: Entry): void {
      buf[head] = entry;
      head = (head + 1) % MAX_ENTRIES;
      if (count < MAX_ENTRIES) count++;
    },

    entriesAfter(cutoffTs: number): Entry[] {
      const result: Entry[] = [];
      const len = count;
      // Walk from oldest to newest
      const oldest = (head - len + MAX_ENTRIES * 2) % MAX_ENTRIES;
      for (let i = 0; i < len; i++) {
        const e = buf[(oldest + i) % MAX_ENTRIES];
        if (e !== undefined && e.ts >= cutoffTs) result.push(e);
      }
      return result;
    },

    clear(): void {
      head = 0;
      count = 0;
    },
  };
}

function extractAction(event: ValidatedEvent): Action | null {
  if (event.type === 'policy.evaluated' || event.type === 'policy.denied') {
    return event.data.decision.action;
  }
  return null;
}

function extractTool(event: ValidatedEvent): string {
  if (event.type === 'policy.evaluated' || event.type === 'policy.denied') {
    return event.data.tool;
  }
  if (event.type === 'secret.detected' || event.type === 'mcp.tool_drift') {
    return event.data.tool;
  }
  return event.type;
}

function computeStats(entries: Entry[], windowMs: WindowMs): WindowStats {
  const now = Date.now();
  const total = entries.length;
  const windowSec = windowMs / 1000;

  const distribution: Record<Action, number> = {
    deny: 0, allow: 0, require_approval: 0, audit: 0,
  };
  const toolCounts = new Map<string, number>();
  const latencies: number[] = [];
  let denyCount = 0;

  for (const e of entries) {
    distribution[e.action]++;
    if (e.action === 'deny' || e.action === 'require_approval') denyCount++;
    toolCounts.set(e.tool, (toolCounts.get(e.tool) ?? 0) + 1);
    if (e.latencyNs > 0) latencies.push(e.latencyNs);
  }

  const sorted = latencies.slice().sort((a, b) => a - b);
  const pct = (p: number) => sorted.length > 0 ? (sorted[Math.floor(sorted.length * p)] ?? 0) : 0;

  const topTools = [...toolCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([tool, count]) => ({ tool, count }));

  return {
    windowMs,
    eventRate: total / windowSec,
    denyRate: total > 0 ? denyCount / total : 0,
    distribution,
    topTools,
    p50Ns: pct(0.5),
    p95Ns: pct(0.95),
    p99Ns: pct(0.99),
    computedAt: now,
  };
}

export function createStreamProcessor(): StreamProcessor {
  const buffer = createCircularBuffer();

  return {
    push(event) {
      const action = extractAction(event) ?? 'audit';
      const tool = extractTool(event);
      const latencyNs = event.latencyNs ??
        (event.type === 'policy.evaluated' || event.type === 'policy.denied'
          ? event.data.latency_ns
          : 0);

      buffer.push({ ts: Date.now(), action, tool, latencyNs });
    },

    stats(windowMs) {
      const cutoff = Date.now() - windowMs;
      const entries = buffer.entriesAfter(cutoff);
      return computeStats(entries, windowMs);
    },

    allStats() {
      const now = Date.now();
      return WINDOWS.map((w) => {
        const entries = buffer.entriesAfter(now - w);
        return computeStats(entries, w);
      });
    },

    reset() {
      buffer.clear();
    },
  };
}
