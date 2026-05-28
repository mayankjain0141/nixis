import type { PolicyId } from './branded';

export type AppError =
  | { code: 'STREAM_DISCONNECTED'; lastSeq: number; retryAfterMs: number }
  | { code: 'POLICY_NOT_FOUND'; policyId: PolicyId }
  | { code: 'VALIDATION_FAILED'; field: string; expected: string; received: unknown }
  | { code: 'SEQUENCE_GAP'; expected: number; received: number }
  | { code: 'STALE_DATA'; lastUpdated: number; maxAge: number }
  | { code: 'PARSE_ERROR'; raw: string; error: string }
  | { code: 'INVARIANT_VIOLATED'; invariant: string; evidence: unknown };
