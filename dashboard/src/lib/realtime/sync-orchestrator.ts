// WS-21: Sync Orchestrator
// Three dispatch tiers: IMMEDIATE (flushSync), FRAME (rAF batch), DEFERRED (idle).

import { flushSync } from 'react-dom';

export type DispatchPriority = 'IMMEDIATE' | 'FRAME' | 'DEFERRED';

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

export interface SyncOrchestrator {
  dispatch(update: StoreUpdate): void;
  flush(): void;
  stats(): OrchestratorStats;
}

const DEFAULT_MAX_FRAME_BATCH = 50;
const DEFAULT_MAX_DEFERRED = 200;

export function createSyncOrchestrator(options?: {
  maxFrameBatch?: number;
  maxDeferred?: number;
}): SyncOrchestrator {
  const maxFrameBatch = options?.maxFrameBatch ?? DEFAULT_MAX_FRAME_BATCH;
  const maxDeferred = options?.maxDeferred ?? DEFAULT_MAX_DEFERRED;

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
    // If more remain, schedule another frame.
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

  return {
    dispatch(update) {
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
            deferredQueue.shift(); // drop oldest
            counts.dropped++;
          }
          deferredQueue.push(update);
          scheduleDeferred();
          break;
      }
    },

    flush() {
      // Drain frame queue synchronously (useful for tests and teardown).
      while (frameQueue.length > 0) {
        const u = frameQueue.shift()!;
        u.apply();
        counts.frame++;
      }
      if (rafId !== null) { cancelAnimationFrame(rafId); rafId = null; }

      // Drain deferred queue synchronously.
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
