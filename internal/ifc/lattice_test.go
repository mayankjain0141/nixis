package ifc

import (
	"sync"
	"testing"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// ── Pure lattice function tests ──────────────────────────────────────────────

func TestIFC_Join_IntegrityGoesDown(t *testing.T) {
	// Spec mandates: Join({C:5,I:7}, {C:3,I:3}).Integrity == 3
	a := nixis.SecurityLabel{Confidentiality: 5, Integrity: 7, Category: 0}
	b := nixis.SecurityLabel{Confidentiality: 3, Integrity: 3, Category: 0}
	got := Join(a, b)
	if got.Integrity != 3 {
		t.Errorf("Join.Integrity: want 3, got %d", got.Integrity)
	}
	if got.Confidentiality != 5 {
		t.Errorf("Join.Confidentiality: want 5, got %d", got.Confidentiality)
	}
}

func TestIFC_Join_ConfidentialityGoesUp(t *testing.T) {
	a := nixis.SecurityLabel{Confidentiality: 3, Integrity: 7}
	b := nixis.SecurityLabel{Confidentiality: 9, Integrity: 2}
	got := Join(a, b)
	if got.Confidentiality != 9 {
		t.Errorf("Join.Confidentiality: want 9, got %d", got.Confidentiality)
	}
	if got.Integrity != 2 {
		t.Errorf("Join.Integrity: want 2, got %d", got.Integrity)
	}
}

func TestIFC_Join_CategoryUnion(t *testing.T) {
	a := nixis.SecurityLabel{Category: CatCredentials}
	b := nixis.SecurityLabel{Category: CatFinance}
	got := Join(a, b)
	if got.Category != (CatCredentials | CatFinance) {
		t.Errorf("Join.Category: want %b, got %b", CatCredentials|CatFinance, got.Category)
	}
}

func TestIFC_Meet_IntegrityGoesUp(t *testing.T) {
	a := nixis.SecurityLabel{Confidentiality: 5, Integrity: 3}
	b := nixis.SecurityLabel{Confidentiality: 3, Integrity: 7}
	got := Meet(a, b)
	if got.Integrity != 7 {
		t.Errorf("Meet.Integrity: want 7, got %d", got.Integrity)
	}
	if got.Confidentiality != 3 {
		t.Errorf("Meet.Confidentiality: want 3, got %d", got.Confidentiality)
	}
}

func TestIFC_Meet_CategoryIntersection(t *testing.T) {
	a := nixis.SecurityLabel{Category: CatCredentials | CatFinance}
	b := nixis.SecurityLabel{Category: CatFinance | CatPersonalData}
	got := Meet(a, b)
	if got.Category != CatFinance {
		t.Errorf("Meet.Category: want %b, got %b", CatFinance, got.Category)
	}
}

func TestIFC_Dominates(t *testing.T) {
	tests := []struct {
		name    string
		subject nixis.SecurityLabel
		object  nixis.SecurityLabel
		want    bool
	}{
		{
			name:    "subject dominates object — all dimensions",
			subject: nixis.SecurityLabel{Confidentiality: 10, Integrity: 10, Category: CatCredentials | CatFinance},
			object:  nixis.SecurityLabel{Confidentiality: 5, Integrity: 5, Category: CatCredentials},
			want:    true,
		},
		{
			name:    "subject fails confidentiality check",
			subject: nixis.SecurityLabel{Confidentiality: 4, Integrity: 10, Category: CatCredentials},
			object:  nixis.SecurityLabel{Confidentiality: 5, Integrity: 5, Category: CatCredentials},
			want:    false,
		},
		{
			name:    "subject fails integrity check",
			subject: nixis.SecurityLabel{Confidentiality: 10, Integrity: 4, Category: CatCredentials},
			object:  nixis.SecurityLabel{Confidentiality: 5, Integrity: 5, Category: CatCredentials},
			want:    false,
		},
		{
			name:    "subject fails category superset check",
			subject: nixis.SecurityLabel{Confidentiality: 10, Integrity: 10, Category: CatCredentials},
			object:  nixis.SecurityLabel{Confidentiality: 5, Integrity: 5, Category: CatCredentials | CatFinance},
			want:    false,
		},
		{
			name:    "equal labels — dominates (reflexive)",
			subject: nixis.SecurityLabel{Confidentiality: 5, Integrity: 5, Category: CatCredentials},
			object:  nixis.SecurityLabel{Confidentiality: 5, Integrity: 5, Category: CatCredentials},
			want:    true,
		},
		{
			name:    "zero subject dominates zero object",
			subject: nixis.SecurityLabel{},
			object:  nixis.SecurityLabel{},
			want:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Dominates(tc.subject, tc.object)
			if got != tc.want {
				t.Errorf("Dominates: want %v, got %v", tc.want, got)
			}
		})
	}
}

// TestLattice_JoinDistinctFromElevate verifies that Join and Elevate produce
// different results for the same inputs, specifically on the Integrity dimension.
// This is the P0-09 fix test: the two operations MUST NOT be conflated.
func TestLattice_JoinDistinctFromElevate(t *testing.T) {
	session := nixis.SecurityLabel{Confidentiality: 5, Integrity: 3, Category: 0}
	resource := nixis.SecurityLabel{Confidentiality: 3, Integrity: 7, Category: 0}

	joined := Join(session, resource)
	elevated := elevateLabel(session, resource)

	if joined.Integrity == elevated.Integrity {
		t.Errorf("Join and Elevate must produce different Integrity: Join=%d, Elevate=%d",
			joined.Integrity, elevated.Integrity)
	}
	// Join: Integrity = min(3, 7) = 3 (goes DOWN)
	if joined.Integrity != 3 {
		t.Errorf("Join.Integrity: want 3 (min), got %d", joined.Integrity)
	}
	// Elevate: Integrity = max(3, 7) = 7 (goes UP)
	if elevated.Integrity != 7 {
		t.Errorf("Elevate.Integrity: want 7 (max), got %d", elevated.Integrity)
	}
	// Confidentiality: both use max — same result
	if joined.Confidentiality != elevated.Confidentiality {
		t.Errorf("Confidentiality should match: Join=%d, Elevate=%d",
			joined.Confidentiality, elevated.Confidentiality)
	}
}

// ── Join upper-bound properties ───────────────────────────────────────────────
//
// Under the task spec's Dominates (a.I >= b.I = higher numeric means higher privilege),
// Join(a,b).Integrity = min(a.I, b.I) goes DOWN. This means Join is NOT the LUB under
// this Dominates — it is the GLB (greatest lower bound) for Integrity.
// The Join function is named "LUB" in the formal Biba/BLP sense where lower numeric
// Integrity = higher lattice position, but the task spec uses numeric >= for Dominates.
// The critical property is that Join.Integrity never EXCEEDS either input (it goes down).

func TestIFC_Join_ConfidentialityNeverLess(t *testing.T) {
	a := nixis.SecurityLabel{Confidentiality: 8, Integrity: 12, Category: CatCredentials}
	b := nixis.SecurityLabel{Confidentiality: 4, Integrity: 6, Category: CatFinance}
	j := Join(a, b)
	if j.Confidentiality < a.Confidentiality {
		t.Errorf("Join.Confidentiality %d < a.Confidentiality %d", j.Confidentiality, a.Confidentiality)
	}
	if j.Confidentiality < b.Confidentiality {
		t.Errorf("Join.Confidentiality %d < b.Confidentiality %d", j.Confidentiality, b.Confidentiality)
	}
}

func TestIFC_Join_IntegrityNeverGreater(t *testing.T) {
	// Join.Integrity = min — never exceeds either input
	a := nixis.SecurityLabel{Integrity: 12}
	b := nixis.SecurityLabel{Integrity: 6}
	j := Join(a, b)
	if j.Integrity > a.Integrity {
		t.Errorf("Join.Integrity %d > a.Integrity %d", j.Integrity, a.Integrity)
	}
	if j.Integrity > b.Integrity {
		t.Errorf("Join.Integrity %d > b.Integrity %d", j.Integrity, b.Integrity)
	}
}

// ── SessionLabels tests ───────────────────────────────────────────────────────

func TestIFC_Elevate_IntegrityGoesUp(t *testing.T) {
	s := &SessionLabels{}
	// Start from zero label; elevate with high-I resource.
	resource := nixis.SecurityLabel{Confidentiality: 5, Integrity: 7, Category: 0}
	got := s.Elevate("sess-1", resource)
	if got.Integrity != 7 {
		t.Errorf("Elevate.Integrity: want 7, got %d", got.Integrity)
	}
}

func TestIFC_Elevate_ConcurrentSafe(t *testing.T) {
	// 100 goroutines concurrently elevating the same session.
	// Final label must equal the elevateLabel-join of all inputs.
	// Race detector must find no issues (run with -race).
	const n = 100
	s := &SessionLabels{}
	sessionID := "concurrent-sess"

	var wg sync.WaitGroup
	wg.Add(n)
	inputs := make([]nixis.SecurityLabel, n)
	for i := range inputs {
		inputs[i] = nixis.SecurityLabel{
			Confidentiality: uint16(i),
			Integrity:       uint16(n - i),
			Category:        uint32(i % 4),
		}
	}
	for i := 0; i < n; i++ {
		go func(lbl nixis.SecurityLabel) {
			defer wg.Done()
			s.Elevate(sessionID, lbl)
		}(inputs[i])
	}
	wg.Wait()

	// Compute expected: fold elevateLabel over all inputs starting from zero.
	expected := nixis.SecurityLabel{}
	for _, lbl := range inputs {
		expected = elevateLabel(expected, lbl)
	}

	got := s.Current(sessionID)
	if got.Confidentiality != expected.Confidentiality {
		t.Errorf("Confidentiality: want %d, got %d", expected.Confidentiality, got.Confidentiality)
	}
	if got.Integrity != expected.Integrity {
		t.Errorf("Integrity: want %d, got %d", expected.Integrity, got.Integrity)
	}
	if got.Category != expected.Category {
		t.Errorf("Category: want %d, got %d", expected.Category, got.Category)
	}
}

func TestIFC_Declassify_LabelNotLowered(t *testing.T) {
	s := &SessionLabels{}
	sessionID := "declassify-sess"

	// Elevate the session to a non-zero label.
	high := nixis.SecurityLabel{Confidentiality: 100, Integrity: 50, Category: CatCredentials}
	s.Elevate(sessionID, high)

	before := s.Current(sessionID)

	gate := &DeclassificationGate{AuditRef: "audit-ref-001"}
	ann := gate.Apply(s, sessionID)

	after := s.Current(sessionID)

	// Label must be unchanged.
	if !Equal(before, after) {
		t.Errorf("label must not be lowered: before=%+v, after=%+v", before, after)
	}
	// Annotation must capture the correct label.
	if !Equal(ann.Label, before) {
		t.Errorf("annotation label mismatch: want %+v, got %+v", before, ann.Label)
	}
	if ann.AuditRef != "audit-ref-001" {
		t.Errorf("AuditRef: want audit-ref-001, got %q", ann.AuditRef)
	}
}

func TestIFC_LabelState_Transitions(t *testing.T) {
	s := &SessionLabels{}

	// fresh: new session, no elevation
	if state := s.LabelState("fresh-sess"); state != LabelStateFresh {
		t.Errorf("new session: want fresh, got %q", state)
	}

	// escalated: after normal resource access
	s.Elevate("escalated-sess", nixis.SecurityLabel{Confidentiality: 5, Integrity: 5})
	if state := s.LabelState("escalated-sess"); state != LabelStateEscalated {
		t.Errorf("after normal elevate: want escalated, got %q", state)
	}

	// tainted_by_secret: after TaintWithSecret
	s.TaintWithSecret("tainted-sess")
	if state := s.LabelState("tainted-sess"); state != LabelStateTaintedBySecret {
		t.Errorf("after TaintWithSecret: want tainted_by_secret, got %q", state)
	}

	// declassified: after DeclassificationGate.Apply
	s.Elevate("declassified-sess", nixis.SecurityLabel{Confidentiality: 1})
	gate := &DeclassificationGate{AuditRef: "ref"}
	gate.Apply(s, "declassified-sess")
	if state := s.LabelState("declassified-sess"); state != LabelStateDeclassified {
		t.Errorf("after declassify: want declassified, got %q", state)
	}
}

func TestIFC_TaintWithSecret_SetsTaintBit(t *testing.T) {
	s := &SessionLabels{}
	got := s.TaintWithSecret("taint-sess")
	if got.Category&TaintBit == 0 {
		t.Error("TaintWithSecret must set TaintBit in Category")
	}
	if s.LabelState("taint-sess") != LabelStateTaintedBySecret {
		t.Error("state must be tainted_by_secret after TaintWithSecret")
	}
}

// ── Packing round-trip ────────────────────────────────────────────────────────

func TestPackUnpack_RoundTrip(t *testing.T) {
	labels := []nixis.SecurityLabel{
		{Confidentiality: 0, Integrity: 0, Category: 0},
		{Confidentiality: 65535, Integrity: 65535, Category: 0xFFFFFFFF},
		{Confidentiality: 24576, Integrity: 32768, Category: CatCredentials | CatSecurityKey},
		{Confidentiality: 1, Integrity: 1, Category: TaintBit},
	}
	for _, l := range labels {
		got := unpackLabel(packLabel(l))
		if !Equal(got, l) {
			t.Errorf("round-trip failed: want %+v, got %+v", l, got)
		}
	}
}
