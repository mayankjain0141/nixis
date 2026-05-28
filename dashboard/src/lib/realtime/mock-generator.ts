// WS-25: Mock Data Generator
// Produces ValidatedEvent[] with seeded PRNG (same seed → same sequence).
// All SecurityLabels are numeric (ADR-013). All verdicts are canonical (ADR-014).

import type { ValidatedEvent } from './ingestion-pipeline';

// ── Seeded PRNG (Knuth multiplicative LCG, kept in uint32) ───────────────────

function lcg(seed: number): number {
  return ((seed * 1664525 + 1013904223) >>> 0);
}

// ── Canonical vocabulary ──────────────────────────────────────────────────────

const VERDICTS = ['deny', 'allow', 'require_approval', 'audit'] as const;
type Verdict = typeof VERDICTS[number];

const TOOLS = ['Shell', 'Read', 'Write', 'Edit', 'Bash', 'WebFetch', 'WebSearch', 'GitCommit', 'GitPush'];
const POLICIES = ['builtin:readonly-adapter', 'builtin:protected-branches', 'builtin:no-secrets', 'team:custom'];
const LAYERS = ['adapter', 'cel', 'ifc', 'delegation', 'secret-scan'] as const;

// ── SecurityLabel generation (always numeric — ADR-013) ────────────────────

function makeLabel(seed: number): { confidentiality: number; integrity: number; categories: number } {
  const s = seed >>> 0;
  return {
    confidentiality: (s % 4) * 16384,
    integrity: ((s >>> 4) % 4) * 16384,
    categories: (s >>> 8) % 8,
  };
}

function makeSessionId(index: number): string {
  return `sess_${index.toString(16).padStart(8, '0')}`;
}

// ── ValidatedEvent builders per type ─────────────────────────────────────────

function makePolicyEvent(
  seq: number,
  seed: number,
  type: 'policy.evaluated' | 'policy.denied',
): ValidatedEvent {
  const verdict: Verdict = VERDICTS[seed % VERDICTS.length];
  const tool = TOOLS[(seed >>> 4) % TOOLS.length];
  const policy = POLICIES[(seed >>> 8) % POLICIES.length];
  const layer = LAYERS[(seed >>> 12) % LAYERS.length];
  const labelSeed = seed >>> 16;

  return {
    type,
    envelope: {
      type,
      aegissequence: seq,
      id: `evt-${seq}`,
      time: new Date(Date.now() + seq * 100).toISOString(),
    },
    data: {
      tool,
      session_id: makeSessionId((seed >>> 20) % 8),
      decision: {
        action: verdict,
        reason: verdict === 'deny' ? 'Policy rule matched' : '',
        policy_id: policy,
        enforcing_layer: layer,
        labels: makeLabel(labelSeed),
      },
      label_state: 'fresh',
      latency_ns: (seed % 10) * 500_000 + 100_000,
    },
  };
}

function makeHeartbeatEvent(seq: number): ValidatedEvent {
  return {
    type: 'stream.heartbeat',
    envelope: { type: 'stream.heartbeat', aegissequence: seq, id: `hb-${seq}` },
    data: { serverTime: Date.now(), lag: 0, sequence: seq },
  };
}

function makeDelegationEvent(
  seq: number,
  seed: number,
  type: 'delegation.created' | 'delegation.revoked' | 'delegation.expired',
): ValidatedEvent {
  return {
    type,
    envelope: { type, aegissequence: seq, id: `del-${seq}` },
    data: {
      chain_id: `chain-${seed % 100}`,
      issuer: makeSessionId(seed % 4),
      subject: makeSessionId((seed >>> 8) % 4),
      expires_at: Date.now() + 3_600_000,
    },
  };
}

function makeSecretDetectedEvent(seq: number, seed: number): ValidatedEvent {
  return {
    type: 'secret.detected',
    envelope: { type: 'secret.detected', aegissequence: seq, id: `sec-${seq}` },
    data: {
      session_id: makeSessionId(seed % 4),
      tool: TOOLS[seed % TOOLS.length],
      rule_id: 'aws-access-key',
      severity: 'critical',
      label: makeLabel(seed >>> 8),
    },
    priority: 'CRITICAL',
  };
}

function makeLabelEscalatedEvent(seq: number, seed: number): ValidatedEvent {
  return {
    type: 'label.escalated',
    envelope: { type: 'label.escalated', aegissequence: seq, id: `lbl-${seq}` },
    data: {
      session_id: makeSessionId(seed % 4),
      label: makeLabel(seed >>> 4),
      label_state: 'escalated',
    },
    priority: 'CRITICAL',
  };
}

function makeAuditCheckpointEvent(seq: number, seed: number): ValidatedEvent {
  return {
    type: 'audit.checkpoint',
    envelope: { type: 'audit.checkpoint', aegissequence: seq, id: `ckpt-${seq}` },
    data: {
      hash: `sha256:${seed.toString(16).padStart(64, '0')}`,
      prevHash: `sha256:${(seed - 1).toString(16).padStart(64, '0')}`,
      eventCount: seq,
    },
  };
}

function makeBundleActivatedEvent(seq: number, seed: number): ValidatedEvent {
  return {
    type: 'bundle.activated',
    envelope: { type: 'bundle.activated', aegissequence: seq, id: `bndl-${seq}` },
    data: {
      version: (seed % 100) + 1,
      previousVersion: seed % 100,
      hash: `sha256:bundle${seed.toString(16).padStart(60, '0')}`,
      signatureVerified: true,
      policyCount: (seed % 50) + 1,
      adapterCount: (seed % 400) + 100,
    },
  };
}

function makeSystemErrorEvent(seq: number, seed: number): ValidatedEvent {
  return {
    type: 'system.error',
    envelope: { type: 'system.error', aegissequence: seq, id: `err-${seq}` },
    data: {
      subsystem: 'audit',
      error: `Error #${seed % 100}`,
      severity: 'high',
    },
  };
}

function makeMcpToolDriftEvent(seq: number, seed: number): ValidatedEvent {
  return {
    type: 'mcp.tool_drift',
    envelope: { type: 'mcp.tool_drift', aegissequence: seq, id: `drift-${seq}` },
    data: {
      tool: TOOLS[seed % TOOLS.length],
      previous_hash: `sha256:prev${seed.toString(16).padStart(60, '0')}`,
      current_hash: `sha256:curr${(seed + 1).toString(16).padStart(60, '0')}`,
    },
  };
}

// ── Event type round-robin ────────────────────────────────────────────────────

type EventBuilderFn = (seq: number, seed: number) => ValidatedEvent;

const EVENT_BUILDERS: EventBuilderFn[] = [
  (seq, seed) => makePolicyEvent(seq, seed, 'policy.evaluated'),
  (seq, seed) => makePolicyEvent(seq, seed, 'policy.denied'),
  makeHeartbeatEvent,
  (seq, seed) => makeDelegationEvent(seq, seed, 'delegation.created'),
  (seq, seed) => makeDelegationEvent(seq, seed, 'delegation.revoked'),
  (seq, seed) => makeDelegationEvent(seq, seed, 'delegation.expired'),
  makeSecretDetectedEvent,
  makeLabelEscalatedEvent,
  makeAuditCheckpointEvent,
  makeBundleActivatedEvent,
  makeSystemErrorEvent,
  makeMcpToolDriftEvent,
];

// ── Public interface ──────────────────────────────────────────────────────────

export interface MockGeneratorConfig {
  ratePerSecond: number;
  seed: number;
  eventMix?: Record<string, number>; // reserved for future weighted mix; currently unused
}

export interface IMockGenerator {
  start(config: MockGeneratorConfig): void;
  stop(): void;
  generateBatch(count: number): ValidatedEvent[];
}

export function createMockGenerator(): IMockGenerator {
  let timer: ReturnType<typeof setInterval> | null = null;
  let globalSeq = 0;
  let currentSeed = 0;

  function nextSeed(): number {
    currentSeed = lcg(currentSeed);
    return currentSeed;
  }

  function generateOne(seq: number): ValidatedEvent {
    const seed = nextSeed();
    const builderIndex = (seq - 1) % EVENT_BUILDERS.length;
    return EVENT_BUILDERS[builderIndex](seq, seed);
  }

  return {
    generateBatch(count: number): ValidatedEvent[] {
      const events: ValidatedEvent[] = [];
      for (let i = 0; i < count; i++) {
        globalSeq++;
        events.push(generateOne(globalSeq));
      }
      return events;
    },

    start(config: MockGeneratorConfig): void {
      if (timer !== null) return;
      currentSeed = config.seed;
      globalSeq = 0;
      const intervalMs = Math.floor(1000 / config.ratePerSecond);
      timer = setInterval(() => {
        globalSeq++;
        generateOne(globalSeq); // side-effect: advances seed
      }, intervalMs);
    },

    stop(): void {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
    },
  };
}

// ── Seeded batch generator (pure, stateless) ──────────────────────────────────
// generateBatch(count, seed) with an explicit seed allows deterministic testing.

export function generateBatch(count: number, seed: number): ValidatedEvent[] {
  const events: ValidatedEvent[] = [];
  let s = seed;
  for (let i = 0; i < count; i++) {
    s = lcg(s);
    const seq = i + 1;
    const builderIndex = i % EVENT_BUILDERS.length;
    events.push(EVENT_BUILDERS[builderIndex](seq, s));
  }
  return events;
}
