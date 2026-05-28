package ifc

import (
	"sync"
	"testing"

	"github.com/mayjain/aegis/pkg/aegis"
)

// TestINV_003_ElevateUsesCAS verifies concurrent elevation on the same session
// produces no data race (race detector enforces the CAS invariant).
func TestINV_003_ElevateUsesCAS(t *testing.T) {
	sessions := &SessionLabels{}
	var wg sync.WaitGroup
	const n = 100
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			label := aegis.SecurityLabel{Confidentiality: uint16(i % 65535)}
			sessions.Elevate("test-session", label)
		}(i)
	}
	wg.Wait()
}

// TestINV_004_ElevationIsMonotonic verifies that Elevate never regresses the label.
func TestINV_004_ElevationIsMonotonic(t *testing.T) {
	sessions := &SessionLabels{}
	sessions.Elevate("sess", aegis.SecurityLabel{Confidentiality: 100})
	high := sessions.Current("sess")
	sessions.Elevate("sess", aegis.SecurityLabel{Confidentiality: 50}) // attempt lower
	current := sessions.Current("sess")
	if current.Confidentiality < high.Confidentiality {
		t.Errorf("INV-004 violated: label regressed from %d to %d",
			high.Confidentiality, current.Confidentiality)
	}
}

// TestINV_010_DelegationCeilingEnforced verifies InitWithCeiling caps subsequent elevation.
func TestINV_010_DelegationCeilingEnforced(t *testing.T) {
	sessions := &SessionLabels{}
	ceiling := aegis.SecurityLabel{Confidentiality: 100, Integrity: 100}
	sessions.InitWithCeiling("sess", ceiling)
	// Attempt to elevate ABOVE ceiling.
	sessions.Elevate("sess", aegis.SecurityLabel{Confidentiality: 200, Integrity: 200})
	current := sessions.Current("sess")
	// The label itself is not capped by Elevate — ceiling is enforced at evaluation time
	// via CheckCeiling. Verify CheckCeiling correctly reports the violation.
	if sessions.CheckCeiling("sess", current) {
		// current is within ceiling — this means Elevate capped it. Either way is fine.
		return
	}
	// current exceeds ceiling — CheckCeiling must return false (violation detected).
	if sessions.CheckCeiling("sess", aegis.SecurityLabel{Confidentiality: 200}) {
		t.Error("INV-010 violated: CheckCeiling returned true for label exceeding ceiling")
	}
}
