package daemon

import (
	"sync"
	"testing"
	"time"
)

func TestDaemonMode_String(t *testing.T) {
	tests := []struct {
		mode DaemonMode
		want string
	}{
		{ModeNormal, "normal"},
		{ModeDegraded, "degraded"},
		{ModeDenyAll, "deny_all"},
		{ModeReadOnly, "read_only"},
		{DaemonMode(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.mode.String(); got != tt.want {
			t.Errorf("DaemonMode(%d).String() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestDaemonMode_HealthStatus(t *testing.T) {
	tests := []struct {
		mode DaemonMode
		want string
	}{
		{ModeNormal, "healthy"},
		{ModeDegraded, "degraded"},
		{ModeDenyAll, "unhealthy"},
		{ModeReadOnly, "unhealthy"},
	}
	for _, tt := range tests {
		if got := tt.mode.HealthStatus(); got != tt.want {
			t.Errorf("DaemonMode(%d).HealthStatus() = %q, want %q", tt.mode, got, tt.want)
		}
	}
}

func TestModeState_SetAndGet(t *testing.T) {
	var s modeState

	before := time.Now().UnixNano()
	s.Set(ModeDegraded, "audit chain broken")
	after := time.Now().UnixNano()

	mode, reason := s.Get()
	if mode != ModeDegraded {
		t.Errorf("Get() mode = %v, want %v", mode, ModeDegraded)
	}
	if reason != "audit chain broken" {
		t.Errorf("Get() reason = %q, want %q", reason, "audit chain broken")
	}

	setAt := s.SetAt()
	if setAt < before || setAt > after {
		t.Errorf("SetAt() = %d, want in range [%d, %d]", setAt, before, after)
	}
}

func TestModeState_Mode(t *testing.T) {
	var s modeState
	if got := s.Mode(); got != ModeNormal {
		t.Errorf("zero-value Mode() = %v, want %v", got, ModeNormal)
	}
	s.Set(ModeReadOnly, "sqlite write failure")
	if got := s.Mode(); got != ModeReadOnly {
		t.Errorf("Mode() after Set = %v, want %v", got, ModeReadOnly)
	}
}

func TestModeState_ZeroValue(t *testing.T) {
	var s modeState
	mode, reason := s.Get()
	if mode != ModeNormal {
		t.Errorf("zero-value mode = %v, want %v", mode, ModeNormal)
	}
	if reason != "" {
		t.Errorf("zero-value reason = %q, want empty", reason)
	}
}

func TestDaemon_Mode_SetAndGet(t *testing.T) {
	socketPath := testSocketPath()
	cfg := Config{SocketPath: socketPath}
	d := New(cfg, allowEngine{}, nil, nil, nil)

	if got := d.Mode(); got != ModeNormal {
		t.Errorf("initial Mode() = %v, want %v", got, ModeNormal)
	}

	d.SetMode(ModeDegraded, "test degraded")
	if got := d.Mode(); got != ModeDegraded {
		t.Errorf("Mode() after SetMode = %v, want %v", got, ModeDegraded)
	}

	mode, reason := d.ModeWithReason()
	if mode != ModeDegraded {
		t.Errorf("ModeWithReason() mode = %v, want %v", mode, ModeDegraded)
	}
	if reason != "test degraded" {
		t.Errorf("ModeWithReason() reason = %q, want %q", reason, "test degraded")
	}
}

func TestDaemon_Mode_Atomic(t *testing.T) {
	socketPath := testSocketPath()
	cfg := Config{SocketPath: socketPath}
	d := New(cfg, allowEngine{}, nil, nil, nil)

	const goroutines = 10
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				mode := DaemonMode(id % 4)
				d.SetMode(mode, "concurrent test")
			}
		}(i)

		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_ = d.Mode()
				_, _ = d.ModeWithReason()
			}
		}()
	}

	wg.Wait()
}
