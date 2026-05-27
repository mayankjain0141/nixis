// WS-19: Backpressure Controller
// Priority queue with 4 levels. CRITICAL events (denials, secrets, IFC escalations)
// bypass batching and are dispatched immediately via flushSync.
// DENY events are NEVER coalesced — security invariant.

import { flushSync } from 'react-dom';
import type { ValidatedEvent } from './ingestion-pipeline';
import type { PressureLevel } from '../../types/events';

export interface CoalescedSummary {
  tool: string;
  verdict: string;
  count: number;
}

export interface FrameStats {
  queueDepth: number;
  pressure: PressureLevel;
  droppedLow: number;
}

export interface ProcessedBatch {
  immediateEvents: ValidatedEvent[];
  coalescedSummary: CoalescedSummary[];
  frameStats: FrameStats;
}

export interface IBackpressureController {
  submit(events: ValidatedEvent[]): void;
  getPressure(): PressureLevel;
  onOutput(handler: (batch: ProcessedBatch) => void): () => void;
}

// ── Priority classification ───────────────────────────────────────────────────

function eventPriority(event: ValidatedEvent): 0 | 1 | 2 | 3 {
  switch (event.type) {
    case 'policy.denied':
    case 'secret.detected':
    case 'label.escalated':
    case 'mcp.tool_drift':
      return 0; // CRITICAL
    case 'delegation.revoked':
    case 'delegation.expired':
    case 'bundle.activated':
      return 1; // HIGH
    case 'policy.evaluated':
    case 'delegation.created':
      return 2; // NORMAL
    case 'stream.heartbeat':
    case 'audit.checkpoint':
    case 'system.error':
    default:
      return 3; // LOW
  }
}

// A denial verdict inside policy.evaluated (ALLOW events bucket) must also be CRITICAL.
function requiresImmediateDispatch(event: ValidatedEvent): boolean {
  if (eventPriority(event) === 0) return true;
  if (event.type === 'policy.evaluated') {
    const v = event.data.decision.action;
    return v === 'deny' || v === 'require_approval';
  }
  return false;
}

// ── Pressure thresholds ───────────────────────────────────────────────────────

const FRAME_BUDGET: Record<PressureLevel, number> = {
  NORMAL: 100, ELEVATED: 60, HIGH: 30, CRITICAL: 10,
};

function computePressure(depth: number): PressureLevel {
  if (depth >= 1000) return 'CRITICAL';
  if (depth >= 500)  return 'HIGH';
  if (depth >= 200)  return 'ELEVATED';
  return 'NORMAL';
}

// ── Coalescing ────────────────────────────────────────────────────────────────
// Only ALLOW/AUDIT verdicts from policy.evaluated are coalesced.
// DENY and REQUIRE_APPROVAL are structurally excluded by requiresImmediateDispatch.

function coalesceNormals(events: ValidatedEvent[]): { kept: ValidatedEvent[]; summary: CoalescedSummary[] } {
  const buckets = new Map<string, { count: number; representative: ValidatedEvent }>();
  const kept: ValidatedEvent[] = [];

  for (const e of events) {
    if (e.type !== 'policy.evaluated') { kept.push(e); continue; }
    const verdict = e.data.decision.action;
    if (verdict === 'deny' || verdict === 'require_approval') { kept.push(e); continue; }
    const key = `${e.data.tool}|${verdict}`;
    const b = buckets.get(key);
    if (b) { b.count++; } else { buckets.set(key, { count: 1, representative: e }); }
  }

  const summary: CoalescedSummary[] = [];
  for (const [key, { count, representative }] of buckets) {
    if (count === 1) { kept.push(representative); }
    else {
      const [tool, verdict] = key.split('|');
      summary.push({ tool, verdict, count });
    }
  }
  return { kept, summary };
}

// ── Factory ───────────────────────────────────────────────────────────────────

export function createBackpressureController(): IBackpressureController {
  // Four priority queues indexed 0–3.
  const queues: [ValidatedEvent[], ValidatedEvent[], ValidatedEvent[], ValidatedEvent[]] =
    [[], [], [], []];
  const outputHandlers: Array<(batch: ProcessedBatch) => void> = [];
  let droppedLow = 0;

  function depth(): number {
    return queues[0].length + queues[1].length + queues[2].length + queues[3].length;
  }

  function dispatch(batch: ProcessedBatch): void {
    for (const h of outputHandlers) h(batch);
  }

  function flush(): void {
    const pressure = computePressure(depth());

    // Shed LOW-priority events under CRITICAL pressure.
    let shedThisFrame = 0;
    if (pressure === 'CRITICAL') {
      shedThisFrame = queues[3].length;
      droppedLow += shedThisFrame;
      queues[3].length = 0;
    }

    const limit = FRAME_BUDGET[pressure];
    const toProcess: ValidatedEvent[] = [];
    for (let p = 0; p <= 3 && toProcess.length < limit; p++) {
      const take = Math.min(queues[p].length, limit - toProcess.length);
      if (take > 0) toProcess.push(...queues[p].splice(0, take));
    }

    // Emit a stats batch even when all events were shed, so observers see droppedLow.
    if (toProcess.length === 0 && shedThisFrame === 0) return;

    let immediate: ValidatedEvent[];
    let summary: CoalescedSummary[];
    if (pressure !== 'NORMAL') {
      const r = coalesceNormals(toProcess);
      immediate = r.kept;
      summary = r.summary;
    } else {
      immediate = toProcess;
      summary = [];
    }

    // Always dispatch when events were shed (observers need to see droppedLow).
    if (immediate.length === 0 && summary.length === 0 && shedThisFrame === 0) return;
    dispatch({ immediateEvents: immediate, coalescedSummary: summary, frameStats: { queueDepth: depth(), pressure, droppedLow } });
  }

  return {
    submit(events) {
      const critical: ValidatedEvent[] = [];
      for (const e of events) {
        if (requiresImmediateDispatch(e)) { critical.push(e); }
        else { queues[eventPriority(e)].push(e); }
      }

      if (critical.length > 0) {
        // Same-frame guarantee for denials and security events.
        flushSync(() => {
          dispatch({ immediateEvents: critical, coalescedSummary: [], frameStats: { queueDepth: depth(), pressure: 'CRITICAL', droppedLow } });
        });
      }

      if (depth() > 0) flush();
    },

    getPressure() { return computePressure(depth()); },

    onOutput(handler) {
      outputHandlers.push(handler);
      return () => { const i = outputHandlers.indexOf(handler); if (i >= 0) outputHandlers.splice(i, 1); };
    },
  };
}
