// SPDX-License-Identifier: MIT
// Package ifc implements the Information Flow Control lattice for Aegis.
//
// Two operations sound similar but are semantically distinct:
//
//   - Join(a, b): Least Upper Bound. Confidentiality goes UP (max), Integrity goes DOWN
//     (min). This is the mathematical lattice LUB under Bell-LaPadula/Biba. Used for
//     policy reasoning and delegation capability intersection.
//
//   - Elevate(session, resource): Session high-water mark. Both Confidentiality and
//     Integrity go UP (max). Used for session taint propagation. NOT the same as Join.
//     Conflating them breaks lattice antisymmetry and is a security defect.
//
// See docs/planning-corpus/05_INTERFACE_REGISTRY.md IFC-010 and §3.2 of design review.
package ifc

import (
	"github.com/mayjain/aegis/pkg/aegis"
)

// Category bit constants for aegis.SecurityLabel.Category.
const (
	CatCredentials  uint32 = 1 << 0  // bit 0
	CatFinance      uint32 = 1 << 1  // bit 1
	CatPersonalData uint32 = 1 << 2  // bit 2
	CatInternal     uint32 = 1 << 3  // bit 3
	CatSecurityKey  uint32 = 1 << 30 // bit 30 — high-value asset
	TaintBit        uint32 = 1 << 31 // bit 31 — tainted_by_secret sentinel
)

// LabelState is the session label lifecycle state machine.
type LabelState string

const (
	LabelStateFresh           LabelState = "fresh"
	LabelStateEscalated       LabelState = "escalated"
	LabelStateTaintedBySecret LabelState = "tainted_by_secret"
	LabelStateDeclassified    LabelState = "declassified"
)

// packLabel packs a SecurityLabel into a uint64 for atomic operations.
// Layout: [Confidentiality:16][Integrity:16][Category:32]
func packLabel(l aegis.SecurityLabel) uint64 {
	return uint64(l.Confidentiality)<<48 | uint64(l.Integrity)<<32 | uint64(l.Category)
}

// unpackLabel unpacks a uint64 into a SecurityLabel.
func unpackLabel(v uint64) aegis.SecurityLabel {
	return aegis.SecurityLabel{
		Confidentiality: uint16(v >> 48),
		Integrity:       uint16(v >> 32),
		Category:        uint32(v),
	}
}

// Join computes the lattice Least Upper Bound (LUB) under Bell-LaPadula + Biba.
//
// Semantics:
//   - Confidentiality: max(a, b) — taint propagates to higher confidentiality
//   - Integrity:       min(a, b) — integrity goes DOWN in Join (Bell-LaPadula)
//   - Category:        a.Category | b.Category — union of all category bits
//
// Note on Integrity direction: Join uses min(Integrity) per Bell-LaPadula. This is
// intentionally asymmetric with Dominates (which uses >=). The Join result dominates
// neither a nor b in the Integrity dimension when a.I != b.I — it represents the
// combined taint of both labels flowing to a common point.
//
// Do NOT use for session high-water mark updates — use Elevate instead.
// Use for: policy evaluation, delegation capability reasoning.
//
//go:nosplit
func Join(a, b aegis.SecurityLabel) aegis.SecurityLabel {
	c := a.Confidentiality
	if b.Confidentiality > c {
		c = b.Confidentiality
	}
	i := a.Integrity
	if b.Integrity < i {
		i = b.Integrity
	}
	return aegis.SecurityLabel{
		Confidentiality: c,
		Integrity:       i,
		Category:        a.Category | b.Category,
	}
}

// Meet computes the Greatest Lower Bound (GLB) of two labels under the Dominates partial order.
//
// Semantics (inverse of Join):
//   - Confidentiality: min(a, b)
//   - Integrity:       max(a, b)
//   - Category:        a.Category & b.Category — intersection of category bits
//
// Use for: delegation capability intersection.
//
//go:nosplit
func Meet(a, b aegis.SecurityLabel) aegis.SecurityLabel {
	c := a.Confidentiality
	if b.Confidentiality < c {
		c = b.Confidentiality
	}
	i := a.Integrity
	if b.Integrity > i {
		i = b.Integrity
	}
	return aegis.SecurityLabel{
		Confidentiality: c,
		Integrity:       i,
		Category:        a.Category & b.Category,
	}
}

// Dominates returns true if subject dominates object (subject >= object in all dimensions).
//
// Bell-LaPadula: subject.Confidentiality >= object.Confidentiality
// Biba:          subject.Integrity >= object.Integrity
//
//	(This implementation uses higher numeric = higher privilege for both dimensions.)
//
// Category:      (subject.Category & object.Category) == object.Category
//
//	subject must be a superset of the object's required categories.
//
//go:nosplit
func Dominates(subject, object aegis.SecurityLabel) bool {
	return subject.Confidentiality >= object.Confidentiality &&
		subject.Integrity >= object.Integrity &&
		(subject.Category&object.Category) == object.Category
}

// Equal compares two labels for equality.
//
//go:nosplit
func Equal(a, b aegis.SecurityLabel) bool {
	return a.Confidentiality == b.Confidentiality &&
		a.Integrity == b.Integrity &&
		a.Category == b.Category
}

// elevateLabel computes the session taint result of accessing a resource.
//
// DIFFERENT from Join: Elevate uses max(Integrity) — integrity goes UP on session taint.
// Join uses min(Integrity) — integrity goes DOWN in the mathematical LUB.
// Conflating these two operations is a security defect (breaks antisymmetry).
//
// Semantics:
//   - Confidentiality: max(session, resource)
//   - Integrity:       max(session, resource)  ← GOES UP (unlike Join)
//   - Category:        session.Category | resource.Category
func elevateLabel(session, resource aegis.SecurityLabel) aegis.SecurityLabel {
	c := session.Confidentiality
	if resource.Confidentiality > c {
		c = resource.Confidentiality
	}
	i := session.Integrity
	if resource.Integrity > i {
		i = resource.Integrity
	}
	return aegis.SecurityLabel{
		Confidentiality: c,
		Integrity:       i,
		Category:        session.Category | resource.Category,
	}
}

// DeclassificationAnnotation records a declassification request without lowering the label.
// The label field captures the label at annotation time — it is NOT altered.
type DeclassificationAnnotation struct {
	SessionID string
	AuditRef  string
	Label     aegis.SecurityLabel // label at time of declassification request
}

// DeclassificationGate records a declassification annotation.
// It MUST NOT lower the session label. RISK-026 mitigation.
type DeclassificationGate struct {
	AuditRef string
}

// Apply records a declassification annotation and returns it.
// It does NOT lower the session label. The label in the returned annotation
// reflects the current session label at call time (unchanged). RISK-026.
func (g *DeclassificationGate) Apply(s *SessionLabels, sessionID string) DeclassificationAnnotation {
	current := s.Current(sessionID)
	// Mark declassified in state machine WITHOUT touching the label.
	// Store() on the label field is explicitly FORBIDDEN here (RISK-026).
	s.markDeclassified(sessionID)
	return DeclassificationAnnotation{
		SessionID: sessionID,
		AuditRef:  g.AuditRef,
		Label:     current,
	}
}
