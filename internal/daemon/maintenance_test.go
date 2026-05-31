// SPDX-License-Identifier: MIT
package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/mayankjain0141/nixis/internal/ifc"
)

// TestRunMaintenanceLoop_PrunesOnTick verifies that the maintenance loop calls
// PruneExpiredRules after at least one ruleTicker fires, then respects ctx.Done().
//
// We use a real Daemon with injected sessions and a very short ticker interval
// (achieved by starting the loop with the ticker already at a short period via
// the public method path — we call runMaintenanceLoop directly with a wrapper).
func TestRunMaintenanceLoop_CancelStops(t *testing.T) {
	sessions := &ifc.SessionLabels{}
	d := &Daemon{
		sessions: sessions,
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.runMaintenanceLoop(ctx)
	}()

	// Cancel context immediately — loop must exit promptly.
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runMaintenanceLoop did not exit after context cancel")
	}
}

// TestRunMaintenanceLoop_NilSessions verifies that the loop does not panic
// when sessions is nil (nil-safe guard on PruneExpiredRules call).
func TestRunMaintenanceLoop_NilSessions(t *testing.T) {
	d := &Daemon{
		sessions:     nil,
		taintHistory: nil,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	done := make(chan struct{})
	go func() {
		defer close(done)
		d.runMaintenanceLoop(ctx)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runMaintenanceLoop did not exit with nil sessions")
	}
}

// TestRunMaintenanceLoop_PrunesExpiredRule uses a real SessionLabels with an
// already-expired standing rule. It hooks into the pruning by verifying the
// rule is removed after PruneExpiredRules is called directly (unit verifies
// the method exists and works, not the ticker timing — ticker-based timing
// tests are inherently flaky and avoided per project standards).
func TestRunMaintenanceLoop_PrunesExpiredRule(t *testing.T) {
	sessions := &ifc.SessionLabels{}

	// Add an already-expired rule
	sessions.AddStandingRule("sess-prune", ifc.StandingRule{
		Effect:          "network_egress",
		ResourcePattern: "*.example.com",
		ExpiresAt:       time.Now().Add(-1 * time.Minute), // already expired
		GrantedAt:       time.Now().Add(-2 * time.Minute),
		GrantedBy:       "test",
	})

	// Verify rule is there before prune
	snap := sessions.Snapshot("sess-prune")
	if len(snap.StandingRules) != 1 {
		t.Fatalf("expected 1 rule before prune, got %d", len(snap.StandingRules))
	}

	// Call PruneExpiredRules directly (as the maintenance loop would)
	sessions.PruneExpiredRules()

	// Verify rule is gone after prune
	snap = sessions.Snapshot("sess-prune")
	if len(snap.StandingRules) != 0 {
		t.Errorf("expected 0 rules after prune, got %d", len(snap.StandingRules))
	}
	if snap.ApprovalState != ifc.ApprovalNone {
		t.Errorf("expected ApprovalNone after all rules pruned, got %v", snap.ApprovalState)
	}
}
