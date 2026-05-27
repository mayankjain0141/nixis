// Canonical verdict vocabulary per ADR-014. Never use 'escalate', 'HITL', or 'block'.
export const VERDICTS = ['deny', 'allow', 'require_approval', 'audit'] as const;
export type Verdict = typeof VERDICTS[number];

// Connection states for the WebSocket manager.
export type ConnectionState =
  | 'IDLE'
  | 'CONNECTING'
  | 'CONNECTED'
  | 'DISCONNECTED'
  | 'RECONNECTING';

// Pressure levels for the backpressure controller (WS-19).
export type PressureLevel = 'NORMAL' | 'ELEVATED' | 'HIGH' | 'CRITICAL';

// Label state values from the IFC lattice (IFC-002).
export type LabelState = 'fresh' | 'escalated' | 'tainted_by_secret' | 'declassified';
