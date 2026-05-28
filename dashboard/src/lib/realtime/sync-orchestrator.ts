// WS-21: Sync Orchestrator
// Three-tier dispatch: IMMEDIATE (flushSync), FRAME (rAF batch), DEFERRED (idle).
// Atomic cross-store transactions: multi-store updates for one event commit together.

import { flushSync } from 'react-dom';
import type { ProcessedBatch } from './backpressure';
import type { ValidatedEvent } from './ingestion-pipeline';
import type { IStreamProcessor } from './stream-processor';

export type DispatchPriority = 'IMMEDIATE' | 'FRAME' | 'DEFERRED';
export type SyncTier = DispatchPriority;

// A StoreUpdate is an atomic unit: all stores updated in its `apply` are committed
// in one Zustand transaction (single set() call in the calling code).
export interface StoreUpdate {
  apply: () => void;
  priority: DispatchPriority;
  eventType: string;
}

export interface OrchestratorStats {
  immediate: number;
  frame: number;
  deferred: number;
  dropped: number;
}

export interface ISyncOrchestrator {
  // Primary entry point: consumes a ProcessedBatch from the backpressure controller.
  dispatch(batch: ProcessedBatch): void;
  // Secondary entry point: dispatch a single pre-classified store update.
  dispatchUpdate(update: StoreUpdate): void;
  flush(): void;
  stats(): OrchestratorStats;
}

// ── Priority classification for individual events ─────────────────────────────

export function eventPriority(event: ValidatedEvent): DispatchPriority {
  switch (event.type) {
    case 'policy.denied':
    case 'secret.detected':
    case 'label.escalated':
    case 'mcp.tool_drift':
      return 'IMMEDIATE';
    case 'delegation.revoked':
    case 'delegation.expired':
    case 'bundle.activated':
    case 'policy.evaluated':
    case 'delegation.created':
      return 'FRAME';
    case 'stream.heartbeat':
    case 'audit.checkpoint':
    case 'system.error':
    default:
      return 'DEFERRED';
  }
}

const DEFAULT_MAX_FRAME_BATCH = 50;
const DEFAULT_MAX_DEFERRED = 200;

export function createSyncOrchestrator(options?: {
  maxFrameBatch?: number;
  maxDeferred?: number;
  onEvent?: (event: ValidatedEvent, priority: DispatchPriority) => void;
  // WS-20 integration: stream processor that processes each batch before store dispatch.
  streamProcessor?: IStreamProcessor;
}): ISyncOrchestrator {
  const maxFrameBatch = options?.maxFrameBatch ?? DEFAULT_MAX_FRAME_BATCH;
  const maxDeferred = options?.maxDeferred ?? DEFAULT_MAX_DEFERRED;
  const onEvent = options?.onEvent;
  const streamProcessor = options?.streamProcessor;

  const frameQueue: StoreUpdate[] = [];
  const deferredQueue: StoreUpdate[] = [];
  let rafId: ReturnType<typeof requestAnimationFrame> | null = null;
  let idleId: number | null = null;

  const counts: OrchestratorStats = { immediate: 0, frame: 0, deferred: 0, dropped: 0 };

  function flushFrame(): void {
    rafId = null;
    const batch = frameQueue.splice(0, maxFrameBatch);
    if (batch.length === 0) return;
    for (const u of batch) {
      u.apply();
      counts.frame++;
    }
    if (frameQueue.length > 0) scheduleFrame();
  }

  function flushDeferred(): void {
    idleId = null;
    const u = deferredQueue.shift();
    if (u === undefined) return;
    u.apply();
    counts.deferred++;
    if (deferredQueue.length > 0) scheduleDeferred();
  }

  function scheduleFrame(): void {
    if (rafId !== null) return;
    rafId = requestAnimationFrame(flushFrame);
  }

  function scheduleDeferred(): void {
    if (idleId !== null) return;
    if (typeof requestIdleCallback !== 'undefined') {
      idleId = requestIdleCallback(flushDeferred);
    } else {
      idleId = setTimeout(flushDeferred, 0) as unknown as number;
    }
  }

  function dispatchUpdate(update: StoreUpdate): void {
    switch (update.priority) {
      case 'IMMEDIATE':
        flushSync(() => update.apply());
        counts.immediate++;
        break;
      case 'FRAME':
        frameQueue.push(update);
        scheduleFrame();
        break;
      case 'DEFERRED':
        if (deferredQueue.length >= maxDeferred) {
          deferredQueue.shift();
          counts.dropped++;
        }
        deferredQueue.push(update);
        scheduleDeferred();
        break;
    }
  }

  return {
    // dispatch consumes a ProcessedBatch from WS-19.
    // Calls WS-20 stream processor first (Interfaces Consumed requirement),
    // then records counts and notifies onEvent hook.
    dispatch(batch: ProcessedBatch) {
      // WS-20: stream processor processes the batch for windowed aggregations.
      if (streamProcessor !== undefined) {
        streamProcessor.process(batch);
      }

      // Record immediate events and notify onEvent hook with per-event priority.
      for (const event of batch.immediateEvents) {
        counts.immediate++;
        if (onEvent) onEvent(event, eventPriority(event));
      }
    },

    dispatchUpdate,

    flush() {
      while (frameQueue.length > 0) {
        const u = frameQueue.shift()!;
        u.apply();
        counts.frame++;
      }
      if (rafId !== null) { cancelAnimationFrame(rafId); rafId = null; }

      while (deferredQueue.length > 0) {
        const u = deferredQueue.shift()!;
        u.apply();
        counts.deferred++;
      }
      if (idleId !== null) {
        if (typeof cancelIdleCallback !== 'undefined') {
          cancelIdleCallback(idleId);
        } else {
          clearTimeout(idleId);
        }
        idleId = null;
      }
    },

    stats() {
      return { ...counts };
    },
  };
}

// ── Atomic cross-store transaction helper ─────────────────────────────────────
// Combines multiple store mutations into one StoreUpdate so they commit atomically.
// Zustand batches multiple set() calls within a single synchronous scope, but
// wrapping in a single apply() guarantees they are submitted together.

export function atomicUpdate(
  priority: DispatchPriority,
  eventType: string,
  ...mutations: Array<() => void>
): StoreUpdate {
  return {
    priority,
    eventType,
    apply() {
      for (const m of mutations) m();
    },
  };
}
