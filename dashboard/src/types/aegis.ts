// Shared TypeScript types mirroring pkg/aegis wire format.
// Field names match the Go struct fields exactly (pkg/aegis/types.go, pkg/aegis/stream.go).

export interface SecurityLabel {
  confidentiality: number; // uint16, 0 = minimum privilege
  integrity: number;       // uint16, 0 = minimum privilege
  category: number;        // uint32 per ADR-016
}

export type Action = 'deny' | 'allow' | 'require_approval' | 'audit';

export interface Decision {
  action: Action;
  reason: string;
  policyId: string;
  labels: SecurityLabel; // scalar, not array (ADR-013)
}

export interface StreamEvent {
  type: string;           // one of the 12 canonical event types
  aegisSequence: number;  // uint64 (JS safe integer range is sufficient)
  sessionId: string;
  tool: string;
  action: Action;
  reason: string;
  label: SecurityLabel;
  timestamp: number;      // unix nanos
}

// 12 canonical event type constants — must match pkg/aegis/stream.go exactly.
export const EVENT_TYPES = {
  DECISION: 'decision',
  LABEL_ESCALATED: 'label.escalated',
  LABEL_TAINTED: 'label.tainted',
  SECRET_FOUND: 'secret.found',
  BUNDLE_ACTIVATED: 'bundle.activated',
  BUNDLE_ROLLEDBACK: 'bundle.rolledback',
  RELOAD_STARTED: 'reload.started',
  RELOAD_COMPLETED: 'reload.completed',
  RELOAD_FAILED: 'reload.failed',
  SESSION_START: 'session.start',
  SESSION_END: 'session.end',
  SYSTEM_ERROR: 'system.error',
} as const;

export type EventType = typeof EVENT_TYPES[keyof typeof EVENT_TYPES];
