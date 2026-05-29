// WS-17: Event Ingestion Pipeline
// Validates CloudEvent envelopes from the WebSocket wire, deduplicates,
// detects sequence gaps, and emits typed ValidatedEvent to downstream consumers.

import { z } from 'zod';
import type { IWebSocketManager, MessageMeta } from './ws-manager';

// ── Wire-format Zod schemas ─────────────────────────────────────────────────

const SecurityLabelSchema = z.object({
  confidentiality: z.number().int().nonnegative(),
  integrity: z.number().int().nonnegative(),
  categories: z.number().int().nonnegative(),
});

const VerdictSchema = z.enum(['deny', 'allow', 'require_approval', 'audit']);

const DecisionSchema = z.object({
  action: VerdictSchema,
  reason: z.string(),
  policy_id: z.string(),
  enforcing_layer: z.string(),
  policy_source: z.string().optional(),
  threat_severity: z.string().optional(),
  labels: SecurityLabelSchema,
});

// CloudEvent envelope — fields present on all events.
const CloudEventEnvelopeSchema = z.object({
  type: z.string(),
  source: z.string().optional(),
  id: z.string().optional(),
  time: z.string().optional(),
  aegissequence: z.number().int().nonnegative(),
  data: z.record(z.string(), z.unknown()).optional(),
});

// Per-type data payload schemas.
const PolicyEvaluatedDataSchema = z.object({
  tool: z.string(),
  arg_hash: z.string().optional(),
  session_id: z.string(),
  decision: DecisionSchema.passthrough(),
  label_state: z.string(),
  latency_ns: z.number(),
  request_args: z.string().optional(),   // actual command/path/query evaluated
}).passthrough();

const PolicyDeniedDataSchema = PolicyEvaluatedDataSchema;

const DelegationDataSchema = z.object({
  chain_id: z.string().optional(),
  issuer: z.string().optional(),
  subject: z.string().optional(),
  expires_at: z.number().optional(),
});

const AuditCheckpointDataSchema = z.object({
  hash: z.string(),
  prevHash: z.string(),
  eventCount: z.number().int(),
  signedTreeHead: z.string().optional(),
});

const StreamHeartbeatDataSchema = z.object({
  serverTime: z.number(),
  lag: z.number().optional(),
  sequence: z.number().int().optional(),
});

const BundlePolicySchema = z.object({
  id: z.string(),
  enabled: z.boolean().default(true),
  layer: z.string().default('cel'),
  cel_expression: z.string().optional(),
  description: z.string().optional(),
}).passthrough();

const BundleActivatedDataSchema = z.object({
  version: z.number().int(),
  previousVersion: z.number().int().optional(),
  hash: z.string().optional().default(''),
  signatureVerified: z.boolean().optional().default(false),
  policyCount: z.number().int().optional().default(0),
  adapterCount: z.number().int().optional().default(0),
  activatedAt: z.number().optional(),
  policies: z.array(BundlePolicySchema).optional(),
}).passthrough();

const LabelEscalatedDataSchema = z.object({
  session_id: z.string(),
  label: SecurityLabelSchema,
  label_state: z.string(),
  previous_label: SecurityLabelSchema.optional(),
});

const SecretDetectedDataSchema = z.object({
  session_id: z.string(),
  tool: z.string(),
  rule_id: z.string().optional(),
  severity: z.string().optional(),
  label: SecurityLabelSchema.optional(),
});

const SystemErrorDataSchema = z.object({
  subsystem: z.string(),
  error: z.string(),
  severity: z.string().optional(),
});

const McpToolDriftDataSchema = z.object({
  tool: z.string(),
  previous_hash: z.string().optional(),
  current_hash: z.string().optional(),
});

// ── ValidatedEvent discriminated union ──────────────────────────────────────

type Envelope = z.infer<typeof CloudEventEnvelopeSchema>;

export interface PolicyEvaluatedEvent { type: 'policy.evaluated'; envelope: Envelope; data: z.infer<typeof PolicyEvaluatedDataSchema> }
export interface PolicyDeniedEvent    { type: 'policy.denied';    envelope: Envelope; data: z.infer<typeof PolicyDeniedDataSchema> }
export interface DelegationCreatedEvent { type: 'delegation.created'; envelope: Envelope; data: z.infer<typeof DelegationDataSchema> }
export interface DelegationRevokedEvent { type: 'delegation.revoked'; envelope: Envelope; data: z.infer<typeof DelegationDataSchema> }
export interface DelegationExpiredEvent { type: 'delegation.expired'; envelope: Envelope; data: z.infer<typeof DelegationDataSchema> }
export interface AuditCheckpointEvent { type: 'audit.checkpoint'; envelope: Envelope; data: z.infer<typeof AuditCheckpointDataSchema> }
export interface StreamHeartbeatEvent { type: 'stream.heartbeat'; envelope: Envelope; data: z.infer<typeof StreamHeartbeatDataSchema> }
export interface BundleActivatedEvent { type: 'bundle.activated'; envelope: Envelope; data: z.infer<typeof BundleActivatedDataSchema> }
export interface LabelEscalatedEvent  { type: 'label.escalated';  envelope: Envelope; data: z.infer<typeof LabelEscalatedDataSchema>; priority: 'CRITICAL' }
export interface SecretDetectedEvent  { type: 'secret.detected';  envelope: Envelope; data: z.infer<typeof SecretDetectedDataSchema>; priority: 'CRITICAL' }
export interface SystemErrorEvent     { type: 'system.error';     envelope: Envelope; data: z.infer<typeof SystemErrorDataSchema> }
export interface McpToolDriftEvent    { type: 'mcp.tool_drift';   envelope: Envelope; data: z.infer<typeof McpToolDriftDataSchema> }

export type ValidatedEvent =
  | PolicyEvaluatedEvent
  | PolicyDeniedEvent
  | DelegationCreatedEvent
  | DelegationRevokedEvent
  | DelegationExpiredEvent
  | AuditCheckpointEvent
  | StreamHeartbeatEvent
  | BundleActivatedEvent
  | LabelEscalatedEvent
  | SecretDetectedEvent
  | SystemErrorEvent
  | McpToolDriftEvent;

export interface IEventIngestionPipeline {
  ingest(raw: string, meta: MessageMeta): void;
  onValidated(handler: (event: ValidatedEvent) => void): () => void;
}

// ── Bloom filter (two-hash FNV, 128Kbit, ~16KB) ──────────────────────────────
// Avoids private class methods (incompatible with erasableSyntaxOnly) by
// using a plain closure-based factory.

const BLOOM_BITS = 131072; // 2^17

function createBloomFilter() {
  const bits = new Uint8Array(BLOOM_BITS >>> 3);

  function fnv1a(s: string, seed: number): number {
    let h = seed;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
    return h % BLOOM_BITS;
  }

  return {
    add(s: string): void {
      const b1 = fnv1a(s, 0x811c9dc5), b2 = fnv1a(s, 0x9747b28c);
      bits[b1 >>> 3] |= (1 << (b1 & 7));
      bits[b2 >>> 3] |= (1 << (b2 & 7));
    },
    mightContain(s: string): boolean {
      const b1 = fnv1a(s, 0x811c9dc5), b2 = fnv1a(s, 0x9747b28c);
      return (bits[b1 >>> 3] & (1 << (b1 & 7))) !== 0
          && (bits[b2 >>> 3] & (1 << (b2 & 7))) !== 0;
    },
  };
}

// ── LRU set ───────────────────────────────────────────────────────────────────

function createLruSet(capacity: number) {
  const map = new Map<string, true>();
  return {
    has(key: string): boolean { return map.has(key); },
    add(key: string): void {
      if (map.has(key)) return;
      if (map.size >= capacity) {
        const oldest = map.keys().next().value;
        if (oldest !== undefined) map.delete(oldest);
      }
      map.set(key, true);
    },
  };
}

// ── Sequence tracker with reorder buffer ─────────────────────────────────────

const REORDER_BUFFER_MAX = 200;
const BACKFILL_DEBOUNCE_MS = 500;

function createSequenceTracker(
  onOrdered: (event: ValidatedEvent) => void,
  onBackfillNeeded: (from: number, to: number) => void,
) {
  let nextExpected = 0;
  const buffer = new Map<number, ValidatedEvent>();
  let backfillTimer: ReturnType<typeof setTimeout> | null = null;
  let pendingGapStart = 0;
  let pendingGapEnd = 0;

  function drain(): void {
    while (buffer.has(nextExpected)) {
      const next = buffer.get(nextExpected)!;
      buffer.delete(nextExpected);
      nextExpected++;
      onOrdered(next);
    }
  }

  return {
    submit(event: ValidatedEvent): void {
      const seq = event.envelope.aegissequence;

      if (nextExpected === 0) { nextExpected = seq + 1; onOrdered(event); return; }
      if (seq === nextExpected) { nextExpected++; onOrdered(event); drain(); return; }
      if (seq < nextExpected) return; // already delivered

      if (buffer.size < REORDER_BUFFER_MAX) buffer.set(seq, event);

      pendingGapStart = nextExpected;
      pendingGapEnd = seq - 1;
      if (backfillTimer !== null) clearTimeout(backfillTimer);
      backfillTimer = setTimeout(() => {
        backfillTimer = null;
        onBackfillNeeded(pendingGapStart, pendingGapEnd);
      }, BACKFILL_DEBOUNCE_MS);
    },
  };
}

// ── Per-type validation dispatch ─────────────────────────────────────────────

function parseValidatedEvent(envelope: Envelope): ValidatedEvent | null {
  const raw = envelope.data ?? {};
  switch (envelope.type) {
    case 'policy.evaluated': { const r = PolicyEvaluatedDataSchema.safeParse(raw); return r.success ? { type: 'policy.evaluated', envelope, data: r.data } : null; }
    case 'policy.denied':    { const r = PolicyDeniedDataSchema.safeParse(raw);    return r.success ? { type: 'policy.denied',    envelope, data: r.data } : null; }
    case 'delegation.created': { const r = DelegationDataSchema.safeParse(raw); return r.success ? { type: 'delegation.created', envelope, data: r.data } : null; }
    case 'delegation.revoked': { const r = DelegationDataSchema.safeParse(raw); return r.success ? { type: 'delegation.revoked', envelope, data: r.data } : null; }
    case 'delegation.expired': { const r = DelegationDataSchema.safeParse(raw); return r.success ? { type: 'delegation.expired', envelope, data: r.data } : null; }
    case 'audit.checkpoint': { const r = AuditCheckpointDataSchema.safeParse(raw); return r.success ? { type: 'audit.checkpoint', envelope, data: r.data } : null; }
    case 'stream.heartbeat': { const r = StreamHeartbeatDataSchema.safeParse(raw); return r.success ? { type: 'stream.heartbeat', envelope, data: r.data } : null; }
    case 'bundle.activated': { const r = BundleActivatedDataSchema.safeParse(raw); return r.success ? { type: 'bundle.activated', envelope, data: r.data } : null; }
    case 'label.escalated':  { const r = LabelEscalatedDataSchema.safeParse(raw);  return r.success ? { type: 'label.escalated',  envelope, data: r.data, priority: 'CRITICAL' } : null; }
    case 'secret.detected':  { const r = SecretDetectedDataSchema.safeParse(raw);  return r.success ? { type: 'secret.detected',  envelope, data: r.data, priority: 'CRITICAL' } : null; }
    case 'system.error':     { const r = SystemErrorDataSchema.safeParse(raw);     return r.success ? { type: 'system.error',     envelope, data: r.data } : null; }
    case 'mcp.tool_drift':   { const r = McpToolDriftDataSchema.safeParse(raw);    return r.success ? { type: 'mcp.tool_drift',   envelope, data: r.data } : null; }
    default: return null;
  }
}

// ── Public factory ────────────────────────────────────────────────────────────

export function createEventIngestionPipeline(
  wsManager: Pick<IWebSocketManager, 'send'>,
): IEventIngestionPipeline {
  const bloom = createBloomFilter();
  const lruSet = createLruSet(10_000);
  const handlers: Array<(event: ValidatedEvent) => void> = [];

  function emit(event: ValidatedEvent): void {
    for (const h of handlers) h(event);
  }

  const tracker = createSequenceTracker(emit, (from, to) => {
    wsManager.send({ type: 'backfill.request', from, to });
  });

  function dedupKey(envelope: Envelope): string {
    return envelope.id ?? String(envelope.aegissequence);
  }

  return {
    ingest(raw, _meta) {
      let parsed: unknown;
      try { parsed = JSON.parse(raw); } catch { return; }

      const ev = CloudEventEnvelopeSchema.safeParse(parsed);
      if (!ev.success) return;

      const envelope = ev.data;
      const key = dedupKey(envelope);
      if (bloom.mightContain(key) && lruSet.has(key)) return;
      bloom.add(key);
      lruSet.add(key);

      const event = parseValidatedEvent(envelope);
      if (event === null) return;
      tracker.submit(event);
    },

    onValidated(handler) {
      handlers.push(handler);
      return () => { const i = handlers.indexOf(handler); if (i >= 0) handlers.splice(i, 1); };
    },
  };
}
