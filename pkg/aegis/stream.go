// SPDX-License-Identifier: MIT
package aegis

import "context"

// StreamEvent is a governance event published by internal/stream/.
// The event type field uses one of the 12 canonical event type constants.
type StreamEvent struct {
	Type           string        // one of the 12 canonical event types (see constants below)
	AegisSequence  uint64        // monotonic sequence number assigned in the fan-out goroutine at Emit() time
	SessionID      string        // session that produced this event; empty for system events
	Tool           string        // tool involved in the event; empty for non-decision events
	Action         Action        // authorization action for decision events; zero (Deny) for non-decision events
	Reason         string        // human-readable explanation accompanying the event
	Label          SecurityLabel // label state at event time; zero for events that do not carry label context
	Timestamp      int64         // Unix nanoseconds at event creation
	PolicyID       string        // policy that triggered the event; empty if not policy-driven
	EnforcingLayer string        // evaluation layer that raised the event (e.g. "cel", "ifc")
	LabelState     string        // serialized label transition description for label.* events
	LatencyNs      int64         // evaluation duration in nanoseconds for decision events; 0 otherwise
}

// Canonical stream event type constants (15 total — fixed per ADR-011).
//
// Event types:
//   - decision: tool call evaluated; carries Action, Tool, PolicyID, LatencyNs
//   - label.escalated: session label raised to a higher confidentiality or integrity level
//   - label.tainted: session label degraded due to a policy violation
//   - secret.found: secret scanner detected a credential or token in tool args
//   - bundle.activated: new policy bundle successfully loaded and active
//   - bundle.rolledback: policy bundle rolled back to last-known-good after a failed reload
//   - reload.started: policy reload triggered (fsnotify or API)
//   - reload.completed: policy reload succeeded
//   - reload.failed: policy reload failed; previous bundle remains active
//   - session.start: new governance session registered
//   - session.end: governance session ended or expired
//   - system.error: daemon-level error not attributable to a single session
//   - delegation.created: a new delegation chain link was established
//   - delegation.revoked: an active delegation was explicitly revoked
//   - delegation.expired: a delegation expired due to TTL or session end
const (
	EventTypeDecision            = "decision"
	EventTypeLabelEscalated      = "label.escalated"
	EventTypeLabelTainted        = "label.tainted"
	EventTypeSecretFound         = "secret.found"
	EventTypeBundleActivated     = "bundle.activated"
	EventTypeBundleRolledBack    = "bundle.rolledback"
	EventTypeReloadStarted       = "reload.started"
	EventTypeReloadCompleted     = "reload.completed"
	EventTypeReloadFailed        = "reload.failed"
	EventTypeSessionStart        = "session.start"
	EventTypeSessionEnd          = "session.end"
	EventTypeSystemError         = "system.error"
	EventTypeDelegationCreated   = "delegation.created"
	EventTypeDelegationRevoked   = "delegation.revoked"
	EventTypeDelegationExpired   = "delegation.expired"
)

// StreamTap is the injection interface for internal/stream/ to receive events
// without importing internal/audit/ or internal/policy/ (depguard enforced).
type StreamTap interface {
	Emit(ctx context.Context, event StreamEvent)
}

// SnapshotReader is the read-only snapshot access interface for internal/stream/.
// Allows stream to read current policy state without importing internal/policy/.
type SnapshotReader interface {
	LoadSnapshot() *EngineSnapshot
}
