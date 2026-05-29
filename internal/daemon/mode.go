package daemon

import (
	"sync/atomic"
	"time"
)

// DaemonMode represents the operational mode of the daemon.
// Values are ordered from most permissive (ModeNormal) to most restrictive (ModeReadOnly).
type DaemonMode int32

const (
	ModeNormal   DaemonMode = iota // full operation
	ModeDegraded                   // audit chain broken, evaluations continue
	ModeDenyAll                    // no valid policy bundle
	ModeReadOnly                   // SQLite write failure, deny new requests
)

// String returns the human-readable name for the daemon mode.
func (m DaemonMode) String() string {
	switch m {
	case ModeNormal:
		return "normal"
	case ModeDegraded:
		return "degraded"
	case ModeDenyAll:
		return "deny_all"
	case ModeReadOnly:
		return "read_only"
	default:
		return "unknown"
	}
}

// HealthStatus returns the health status string for this mode.
// ModeNormal → "healthy", ModeDegraded → "degraded", others → "unhealthy"
func (m DaemonMode) HealthStatus() string {
	switch m {
	case ModeNormal:
		return "healthy"
	case ModeDegraded:
		return "degraded"
	case ModeDenyAll, ModeReadOnly:
		return "unhealthy"
	default:
		return "unhealthy"
	}
}

// modeState holds the daemon's current operational mode with lock-free access.
// All fields use atomic operations for concurrent read/write safety.
type modeState struct {
	mode   atomic.Int32
	reason atomic.Value // string
	setAt  atomic.Int64 // unix nanos
}

// Set atomically updates the mode, reason, and timestamp.
func (s *modeState) Set(m DaemonMode, reason string) {
	s.mode.Store(int32(m))
	s.reason.Store(reason)
	s.setAt.Store(time.Now().UnixNano())
}

// Get atomically reads the current mode and reason.
func (s *modeState) Get() (DaemonMode, string) {
	reason := s.reason.Load()
	if reason == nil {
		return DaemonMode(s.mode.Load()), ""
	}
	reasonStr, ok := reason.(string)
	if !ok {
		return DaemonMode(s.mode.Load()), ""
	}
	return DaemonMode(s.mode.Load()), reasonStr
}

// Mode returns the current DaemonMode atomically.
func (s *modeState) Mode() DaemonMode {
	return DaemonMode(s.mode.Load())
}

// SetAt returns the unix nano timestamp when the mode was last set.
func (s *modeState) SetAt() int64 {
	return s.setAt.Load()
}
