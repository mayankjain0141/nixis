// WS-20: Stream Processing Layer
// Windowed aggregations (5s/30s/5min/1hr), latency percentiles, OrderedEventList
// (binary-search insertion by aegissequence), and event correlation.

import type { ValidatedEvent } from './ingestion-pipeline';
import type { ProcessedBatch } from './backpressure';

// ── Window identifiers ────────────────────────────────────────────────────────

export type WindowId = 'LAST_5S' | 'LAST_30S' | 'LAST_5MIN' | 'LAST_1HR';
export type WindowMs = 5_000 | 30_000 | 300_000 | 3_600_000;
export const WINDOWS: WindowMs[] = [5_000, 30_000, 300_000, 3_600_000];

const WINDOW_MAP: Record<WindowId, WindowMs> = {
  LAST_5S: 5_000,
  LAST_30S: 30_000,
  LAST_5MIN: 300_000,
  LAST_1HR: 3_600_000,
};

// ── Aggregation types ─────────────────────────────────────────────────────────

export interface WindowedAggregation {
  allow: number;
  deny: number;
  require_approval: number;
  audit: number;
  p50LatencyNs: number;
  p95LatencyNs: number;
  p99LatencyNs: number;
  windowDurationMs: WindowMs;
  eventRate: number;   // events/sec
  denyRate: number;    // 0.0–1.0
}

export interface ThroughputMetrics {
  eventsPerSecond: number;
  peakEventsPerSecond: number;
  totalEvents: number;
}

export interface LatencyMetrics {
  p50Ns: number;
  p95Ns: number;
  p99Ns: number;
  maxNs: number;
}

export interface VerdictMetrics {
  allow: number;
  deny: number;
  require_approval: number;
  audit: number;
  denyRate: number;
}

export interface ToolMetrics {
  topTools: Array<{ tool: string; count: number }>;
  uniqueToolCount: number;
}

export interface IFCMetrics {
  activeEscalations: number;
  totalEscalations: number;
}

export interface PolicyMetrics {
  uniquePoliciesEvaluated: number;
}

export interface DerivedMetrics {
  throughput: ThroughputMetrics;
  latency: LatencyMetrics;
  verdicts: VerdictMetrics;
  tools: ToolMetrics;
  ifc: IFCMetrics;
  policies: PolicyMetrics;
  computedAt: number;
}

export interface ActiveFilters {
  verdicts: Array<'allow' | 'deny' | 'require_approval' | 'audit'>;
  tools: string[];
  minLatencyNs: number;
  maxLatencyNs: number;
}

export interface StreamFilter {
  verdicts?: Array<'allow' | 'deny' | 'require_approval' | 'audit'>;
  tools?: string[];
  minLatencyNs?: number;
  maxLatencyNs?: number;
}

export interface CorrelatedEventGroup {
  primaryEventId: string;
  delegationEvents: ValidatedEvent[];
  policyEvents: ValidatedEvent[];
}

// ── OrderedEventList ──────────────────────────────────────────────────────────
// Maintains strictly increasing order by aegissequence via binary-search insertion.
// Invariant: no two events share the same aegissequence (deduplicated on insert).
// O(log n) per insert; the audit trail NEVER shows events out of order.

const MAX_ORDERED = 10_000;

export class OrderedEventList {
  private readonly events: ValidatedEvent[] = [];

  insert(event: ValidatedEvent): void {
    const seq = event.envelope.aegissequence;
    let lo = 0, hi = this.events.length;
    while (lo < hi) {
      const mid = (lo + hi) >>> 1;
      const midSeq = this.events[mid].envelope.aegissequence;
      if (midSeq === seq) return; // duplicate — drop silently
      if (midSeq < seq) lo = mid + 1;
      else hi = mid;
    }
    this.events.splice(lo, 0, event);
    if (this.events.length > MAX_ORDERED) {
      this.events.splice(0, this.events.length - MAX_ORDERED);
    }
  }

  // Returns the full ordered snapshot (oldest first by aegissequence).
  toArray(): ReadonlyArray<ValidatedEvent> {
    return this.events;
  }

  clear(): void {
    this.events.length = 0;
  }

  get length(): number { return this.events.length; }
}

// ── Circular buffer entry ─────────────────────────────────────────────────────

interface Entry {
  ts: number;
  action: 'allow' | 'deny' | 'require_approval' | 'audit';
  tool: string;
  latencyNs: number;
  sessionId: string;
  policyId: string;
  eventId: string;
}

// Sized to hold sustained high-throughput data within the largest window
// without unbounded growth (oldest entries fall off naturally).
const MAX_ENTRIES = 50_000;

function createCircularBuffer() {
  const buf = new Array<Entry | undefined>(MAX_ENTRIES).fill(undefined);
  let head = 0;
  let count = 0;

  return {
    push(e: Entry): void {
      buf[head] = e;
      head = (head + 1) % MAX_ENTRIES;
      if (count < MAX_ENTRIES) count++;
    },
    entriesAfter(cutoffTs: number): Entry[] {
      const result: Entry[] = [];
      const oldest = (head - count + MAX_ENTRIES * 2) % MAX_ENTRIES;
      for (let i = 0; i < count; i++) {
        const e = buf[(oldest + i) % MAX_ENTRIES];
        if (e !== undefined && e.ts >= cutoffTs) result.push(e);
      }
      return result;
    },
    allEntries(): Entry[] {
      const result: Entry[] = [];
      const oldest = (head - count + MAX_ENTRIES * 2) % MAX_ENTRIES;
      for (let i = 0; i < count; i++) {
        const e = buf[(oldest + i) % MAX_ENTRIES];
        if (e !== undefined) result.push(e);
      }
      return result;
    },
    clear(): void { head = 0; count = 0; },
  };
}

// ── Percentile helper ─────────────────────────────────────────────────────────

function pct(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.floor(sorted.length * p)] ?? 0;
}

// ── Window computation ────────────────────────────────────────────────────────

function computeWindow(entries: Entry[], windowMs: WindowMs): WindowedAggregation {
  let allow = 0, deny = 0, require_approval = 0, audit = 0;
  const latencies: number[] = [];

  for (const e of entries) {
    if (e.action === 'allow') allow++;
    else if (e.action === 'deny') deny++;
    else if (e.action === 'require_approval') require_approval++;
    else audit++;
    if (e.latencyNs > 0) latencies.push(e.latencyNs);
  }

  latencies.sort((a, b) => a - b);
  const total = entries.length;
  const windowSec = windowMs / 1000;
  const denyCount = deny + require_approval;

  return {
    allow, deny, require_approval, audit,
    p50LatencyNs: pct(latencies, 0.5),
    p95LatencyNs: pct(latencies, 0.95),
    p99LatencyNs: pct(latencies, 0.99),
    windowDurationMs: windowMs,
    eventRate: total / windowSec,
    denyRate: total > 0 ? denyCount / total : 0,
  };
}

// ── Derived metrics computation ───────────────────────────────────────────────

function computeMetrics(entries: Entry[], totalEvents: number): DerivedMetrics {
  const now = Date.now();
  const last5s = entries.filter(e => e.ts >= now - 5_000);

  let allow = 0, deny = 0, require_approval = 0, audit = 0;
  const latencies: number[] = [];
  const toolCounts = new Map<string, number>();
  const policyIds = new Set<string>();

  for (const e of entries) {
    if (e.action === 'allow') allow++;
    else if (e.action === 'deny') deny++;
    else if (e.action === 'require_approval') require_approval++;
    else audit++;
    if (e.latencyNs > 0) latencies.push(e.latencyNs);
    toolCounts.set(e.tool, (toolCounts.get(e.tool) ?? 0) + 1);
    if (e.policyId) policyIds.add(e.policyId);
  }

  latencies.sort((a, b) => a - b);
  const topTools = [...toolCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([tool, count]) => ({ tool, count }));

  const total = entries.length;
  const denyCount = deny + require_approval;

  return {
    throughput: {
      eventsPerSecond: last5s.length / 5,
      peakEventsPerSecond: 0,
      totalEvents,
    },
    latency: {
      p50Ns: pct(latencies, 0.5),
      p95Ns: pct(latencies, 0.95),
      p99Ns: pct(latencies, 0.99),
      maxNs: latencies[latencies.length - 1] ?? 0,
    },
    verdicts: {
      allow, deny, require_approval, audit,
      denyRate: total > 0 ? denyCount / total : 0,
    },
    tools: {
      topTools,
      uniqueToolCount: toolCounts.size,
    },
    ifc: {
      activeEscalations: 0,
      totalEscalations: 0,
    },
    policies: {
      uniquePoliciesEvaluated: policyIds.size,
    },
    computedAt: now,
  };
}

// ── Event correlation ─────────────────────────────────────────────────────────
// Links delegation events to the policy evaluation event from the same session
// that immediately precedes them in sequence order.

function buildCorrelationIndex(events: ReadonlyArray<ValidatedEvent>): Map<string, CorrelatedEventGroup> {
  const index = new Map<string, CorrelatedEventGroup>();

  for (const e of events) {
    if (e.type === 'policy.evaluated' || e.type === 'policy.denied') {
      const id = e.envelope.id ?? String(e.envelope.aegissequence);
      if (!index.has(id)) {
        index.set(id, { primaryEventId: id, delegationEvents: [], policyEvents: [e] });
      }
    }
  }

  for (const e of events) {
    if (!e.type.startsWith('delegation.')) continue;
    const sessionId = (e.data as { subject?: string }).subject ?? '';
    let bestId: string | null = null;
    let bestSeq = -1;
    for (const [gid, group] of index) {
      for (const pe of group.policyEvents) {
        const peSessionId = (pe.data as { session_id?: string }).session_id ?? '';
        const peSeq = pe.envelope.aegissequence;
        if (peSessionId === sessionId && peSeq < e.envelope.aegissequence && peSeq > bestSeq) {
          bestId = gid;
          bestSeq = peSeq;
        }
      }
    }
    if (bestId !== null) {
      index.get(bestId)!.delegationEvents.push(e);
    }
  }

  return index;
}

// ── Public interface ──────────────────────────────────────────────────────────

export interface IStreamProcessor {
  // Primary entry point: consumes a ProcessedBatch from the backpressure controller (WS-19).
  // Satisfies the 08_EXECUTION_CONTEXT WS-20 interface: process(batch: ProcessedBatch).
  process(batch: ProcessedBatch): void;
  // Secondary entry point: process a pre-extracted slice of events.
  processBatch(events: ValidatedEvent[]): void;
  getMetrics(): DerivedMetrics;
  getFilters(): ActiveFilters;
  setFilter(filter: StreamFilter): void;
  getWindow(windowId: WindowId): WindowedAggregation;
  getCorrelatedEvents(eventId: string): CorrelatedEventGroup | null;
  onMetricsUpdate(handler: (metrics: DerivedMetrics) => void): () => void;
  reset(): void;
  // Ordered audit trail (insertion-sorted by aegissequence)
  getOrderedEvents(): ReadonlyArray<ValidatedEvent>;
}

export function createStreamProcessor(): IStreamProcessor {
  const buffer = createCircularBuffer();
  const orderedList = new OrderedEventList();
  const metricsHandlers: Array<(m: DerivedMetrics) => void> = [];
  let totalEvents = 0;
  let correlationIndex = new Map<string, CorrelatedEventGroup>();
  let correlationDirty = false;

  const filters: ActiveFilters = {
    verdicts: [],
    tools: [],
    minLatencyNs: 0,
    maxLatencyNs: 0,
  };

  function extractEntry(event: ValidatedEvent): Entry | null {
    if (event.type === 'policy.evaluated' || event.type === 'policy.denied') {
      const d = event.data;
      return {
        ts: Date.now(),
        action: d.decision.action,
        tool: d.tool,
        latencyNs: d.latency_ns,
        sessionId: d.session_id,
        policyId: d.decision.policy_id,
        eventId: event.envelope.id ?? String(event.envelope.aegissequence),
      };
    }
    return null;
  }

  function matchesFilter(event: ValidatedEvent): boolean {
    if (filters.verdicts.length > 0) {
      if (event.type !== 'policy.evaluated' && event.type !== 'policy.denied') return true; // non-policy always passes
      const action = event.data.decision.action;
      if (!filters.verdicts.includes(action)) return false;
    }
    if (filters.tools.length > 0) {
      if (event.type !== 'policy.evaluated' && event.type !== 'policy.denied') return true;
      if (!filters.tools.includes(event.data.tool)) return false;
    }
    return true;
  }

  function emitMetrics(): void {
    if (metricsHandlers.length === 0) return;
    const entries = buffer.allEntries();
    const m = computeMetrics(entries, totalEvents);
    for (const h of metricsHandlers) h(m);
  }

  const processor: IStreamProcessor = {
    // Primary entry: consume WS-19 ProcessedBatch directly.
    process(batch) {
      if (batch.immediateEvents.length > 0) {
        processor.processBatch(batch.immediateEvents);
      }
    },

    processBatch(events) {
      for (const event of events) {
        if (!matchesFilter(event)) continue;
        orderedList.insert(event);
        const entry = extractEntry(event);
        if (entry !== null) {
          buffer.push(entry);
          totalEvents++;
        }
        correlationDirty = true;
      }
      emitMetrics();
    },

    getMetrics() {
      return computeMetrics(buffer.allEntries(), totalEvents);
    },

    getFilters() {
      return { ...filters };
    },

    setFilter(filter) {
      if (filter.verdicts !== undefined) filters.verdicts = filter.verdicts;
      if (filter.tools !== undefined) filters.tools = filter.tools;
      if (filter.minLatencyNs !== undefined) filters.minLatencyNs = filter.minLatencyNs;
      if (filter.maxLatencyNs !== undefined) filters.maxLatencyNs = filter.maxLatencyNs;
    },

    getWindow(windowId) {
      const windowMs = WINDOW_MAP[windowId];
      const cutoff = Date.now() - windowMs;
      const entries = buffer.entriesAfter(cutoff);
      return computeWindow(entries, windowMs);
    },

    getCorrelatedEvents(eventId) {
      if (correlationDirty) {
        correlationIndex = buildCorrelationIndex(orderedList.toArray());
        correlationDirty = false;
      }
      return correlationIndex.get(eventId) ?? null;
    },

    onMetricsUpdate(handler) {
      metricsHandlers.push(handler);
      return () => {
        const i = metricsHandlers.indexOf(handler);
        if (i >= 0) metricsHandlers.splice(i, 1);
      };
    },

    reset() {
      buffer.clear();
      orderedList.clear();
      totalEvents = 0;
      correlationIndex.clear();
      correlationDirty = false;
    },

    getOrderedEvents() {
      return orderedList.toArray();
    },
  };
  return processor;
}
