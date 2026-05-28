package aegis

import "context"

// StreamEvent is a governance event published by internal/stream/.
// The event type field uses one of the 12 canonical event type constants.
type StreamEvent struct {
	Type           string // one of the 12 canonical event types
	AegisSequence  uint64 // assigned in fan-out goroutine at Emit() time
	SessionID      string
	Tool           string
	Action         Action
	Reason         string
	Label          SecurityLabel
	Timestamp      int64
	PolicyID       string
	EnforcingLayer string
	LabelState     string
	LatencyNs      int64
}

// Canonical stream event type constants (12 total — fixed per ADR-011).
const (
	EventTypeDecision         = "decision"
	EventTypeLabelEscalated   = "label.escalated"
	EventTypeLabelTainted     = "label.tainted"
	EventTypeSecretFound      = "secret.found"
	EventTypeBundleActivated  = "bundle.activated"
	EventTypeBundleRolledBack = "bundle.rolledback"
	EventTypeReloadStarted    = "reload.started"
	EventTypeReloadCompleted  = "reload.completed"
	EventTypeReloadFailed     = "reload.failed"
	EventTypeSessionStart     = "session.start"
	EventTypeSessionEnd       = "session.end"
	EventTypeSystemError      = "system.error"
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
