// SPDX-License-Identifier: MIT
package ifc

import (
	"sync"
	"testing"
	"time"

	"github.com/mayjain/nixis/pkg/nixis"
)

// ---- ProjectRoot ----

func TestProjectRoot_UnknownSession_Empty(t *testing.T) {
	sl := newSL()
	if got := sl.ProjectRoot("no-such-session"); got != "" {
		t.Fatalf("expected empty for unknown session, got %q", got)
	}
}

func TestProjectRoot_SetThenGet(t *testing.T) {
	sl := newSL()
	sl.SetProjectRoot("sess-pr-1", "/code/myproject")
	if got := sl.ProjectRoot("sess-pr-1"); got != "/code/myproject" {
		t.Fatalf("expected /code/myproject, got %q", got)
	}
}

func TestProjectRoot_EmptyRootIsNoOp(t *testing.T) {
	sl := newSL()
	sl.SetProjectRoot("sess-pr-2", "")
	if got := sl.ProjectRoot("sess-pr-2"); got != "" {
		t.Fatalf("SetProjectRoot with empty root should be no-op, got %q", got)
	}
	// First non-empty write should still work after the no-op
	sl.SetProjectRoot("sess-pr-2", "/code/real")
	if got := sl.ProjectRoot("sess-pr-2"); got != "/code/real" {
		t.Fatalf("expected /code/real after non-empty set, got %q", got)
	}
}

func TestProjectRoot_FirstWriteWins(t *testing.T) {
	sl := newSL()
	sl.SetProjectRoot("sess-pr-3", "/code/first")
	sl.SetProjectRoot("sess-pr-3", "/code/second") // must be ignored
	if got := sl.ProjectRoot("sess-pr-3"); got != "/code/first" {
		t.Fatalf("expected first write /code/first to win, got %q", got)
	}
}

func TestProjectRoot_ConcurrentFirstWriteWins(t *testing.T) {
	sl := newSL()
	const goroutines = 50
	roots := make([]string, goroutines)
	for i := range roots {
		roots[i] = "/code/goroutine"
	}
	roots[0] = "/code/winner" // deterministic value; all are equal anyway

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		root := roots[i]
		go func() {
			defer wg.Done()
			sl.SetProjectRoot("sess-pr-concurrent", root)
		}()
	}
	wg.Wait()

	got := sl.ProjectRoot("sess-pr-concurrent")
	if got == "" {
		t.Fatal("expected non-empty project root after concurrent sets, got empty")
	}
	// All values are valid (/code/goroutine or /code/winner) — just must be non-empty.
}

// ---- helpers ----

func newSL() *SessionLabels { return &SessionLabels{} }

func futureExpiry() time.Time { return time.Now().Add(30 * time.Minute) }
func pastExpiry() time.Time   { return time.Now().Add(-1 * time.Second) }

func makeRule(effect, pattern string, expiry time.Time) StandingRule {
	return StandingRule{
		Effect:          effect,
		ResourcePattern: pattern,
		ExpiresAt:       expiry,
		GrantedAt:       time.Now(),
		GrantedBy:       "test",
	}
}

// ---- IsTainted ----

func TestIsTainted_UnknownSession_False(t *testing.T) {
	sl := newSL()
	if sl.IsTainted("no-such-session") {
		t.Fatal("expected false for unknown session")
	}
}

func TestIsTainted_FreshSession_False(t *testing.T) {
	sl := newSL()
	sl.getOrCreate("sess-1")
	if sl.IsTainted("sess-1") {
		t.Fatal("expected false for fresh session")
	}
}

func TestIsTainted_AfterTaintWithSecret_True(t *testing.T) {
	sl := newSL()
	sl.TaintWithSecret("sess-2")
	if !sl.IsTainted("sess-2") {
		t.Fatal("expected true after TaintWithSecret")
	}
}

func TestIsTainted_AfterElevateWithoutTaintBit_False(t *testing.T) {
	sl := newSL()
	sl.Elevate("sess-3", nixis.SecurityLabel{Confidentiality: 500, Category: CatInternal})
	if sl.IsTainted("sess-3") {
		t.Fatal("expected false: elevated with non-TaintBit category")
	}
}

// ---- Snapshot ----

func TestSnapshot_UnknownSession_ReturnsZero(t *testing.T) {
	sl := newSL()
	snap := sl.Snapshot("ghost")
	if snap.IsTainted {
		t.Error("IsTainted should be false")
	}
	if snap.ApprovalState != ApprovalNone {
		t.Errorf("ApprovalState should be None, got %d", snap.ApprovalState)
	}
	if snap.StandingRules != nil {
		t.Errorf("StandingRules should be nil, got %v", snap.StandingRules)
	}
	if snap.Label != (nixis.SecurityLabel{}) {
		t.Errorf("Label should be zero, got %v", snap.Label)
	}
}

func TestSnapshot_FreshSession_NotTainted(t *testing.T) {
	sl := newSL()
	sl.getOrCreate("fresh-snap")
	snap := sl.Snapshot("fresh-snap")
	if snap.IsTainted {
		t.Error("fresh session should not be tainted")
	}
	if snap.ApprovalState != ApprovalNone {
		t.Errorf("expected ApprovalNone, got %d", snap.ApprovalState)
	}
}

func TestSnapshot_TaintedSession_IsTaintedTrue(t *testing.T) {
	sl := newSL()
	sl.TaintWithSecret("taint-snap")
	snap := sl.Snapshot("taint-snap")
	if !snap.IsTainted {
		t.Error("expected IsTainted=true after TaintWithSecret")
	}
	if snap.Label.Category&TaintBit == 0 {
		t.Error("snapshot Label should have TaintBit set")
	}
}

func TestSnapshot_WithStandingRules_DefensiveCopy(t *testing.T) {
	sl := newSL()
	rule := makeRule("network_egress", "*.github.com", futureExpiry())
	sl.AddStandingRule("snap-rules", rule)

	snap := sl.Snapshot("snap-rules")
	if len(snap.StandingRules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(snap.StandingRules))
	}

	// Mutate the snapshot slice — must not affect internal state
	snap.StandingRules[0].Effect = "mutated"

	snap2 := sl.Snapshot("snap-rules")
	if snap2.StandingRules[0].Effect != "network_egress" {
		t.Error("snapshot mutation leaked into internal state")
	}
}

func TestSnapshot_ApprovalState_Reflected(t *testing.T) {
	sl := newSL()
	sl.SetApprovalState("appr-snap", ApprovalPending)
	snap := sl.Snapshot("appr-snap")
	if snap.ApprovalState != ApprovalPending {
		t.Errorf("expected Pending, got %d", snap.ApprovalState)
	}
}

func TestSnapshot_ConcurrentModification_Safe(t *testing.T) {
	sl := newSL()
	sid := "concurrent-snap"

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sl.TaintWithSecret(sid)
			sl.Snapshot(sid)
			sl.AddStandingRule(sid, makeRule("network_egress", "*.example.com", futureExpiry()))
			sl.Snapshot(sid)
		}()
	}
	wg.Wait()

	snap := sl.Snapshot(sid)
	if !snap.IsTainted {
		t.Error("concurrent taint should result in tainted session")
	}
}

// ---- SetApprovalState ----

func TestSetApprovalState_RoundTrip(t *testing.T) {
	sl := newSL()
	for _, state := range []ApprovalState{ApprovalPending, ApprovalStandingRule, ApprovalSessionGranted, ApprovalNone} {
		sl.SetApprovalState("appr-rt", state)
		got := ApprovalState(sl.getOrCreate("appr-rt").approvalState.Load())
		if got != state {
			t.Errorf("SetApprovalState(%d): got %d", state, got)
		}
	}
}

func TestSetApprovalState_NewSession_Created(t *testing.T) {
	sl := newSL()
	sl.SetApprovalState("brand-new", ApprovalPending)
	snap := sl.Snapshot("brand-new")
	if snap.ApprovalState != ApprovalPending {
		t.Errorf("expected Pending, got %d", snap.ApprovalState)
	}
}

// ---- AddStandingRule ----

func TestAddStandingRule_SetsApprovalStateToStandingRule(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("add-rule", makeRule("network_egress", "*.github.com", futureExpiry()))
	snap := sl.Snapshot("add-rule")
	if snap.ApprovalState != ApprovalStandingRule {
		t.Errorf("expected StandingRule, got %d", snap.ApprovalState)
	}
	if len(snap.StandingRules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(snap.StandingRules))
	}
}

func TestAddStandingRule_DoesNotDemoteSessionGranted(t *testing.T) {
	sl := newSL()
	sl.SetApprovalState("sg-sess", ApprovalSessionGranted)
	sl.AddStandingRule("sg-sess", makeRule("network_egress", "*.example.com", futureExpiry()))
	snap := sl.Snapshot("sg-sess")
	if snap.ApprovalState != ApprovalSessionGranted {
		t.Errorf("AddStandingRule must not demote SessionGranted, got %d", snap.ApprovalState)
	}
}

func TestAddStandingRule_ConcurrentAdds_Safe(t *testing.T) {
	sl := newSL()
	sid := "concurrent-add"
	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sl.AddStandingRule(sid, makeRule("network_egress", "*.safe.com", futureExpiry()))
		}()
	}
	wg.Wait()

	snap := sl.Snapshot(sid)
	if len(snap.StandingRules) != n {
		t.Errorf("expected %d rules after concurrent adds, got %d", n, len(snap.StandingRules))
	}
	if snap.ApprovalState != ApprovalStandingRule {
		t.Errorf("expected StandingRule state, got %d", snap.ApprovalState)
	}
}

// ---- MatchesStandingRule ----

func TestMatchesStandingRule_UnknownSession_NoMatch(t *testing.T) {
	sl := newSL()
	ok, rule := sl.MatchesStandingRule("ghost", "network_egress", "api.github.com")
	if ok || rule != nil {
		t.Error("expected no match for unknown session")
	}
}

func TestMatchesStandingRule_ExactDomain_Matches(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("exact", makeRule("network_egress", "api.github.com", futureExpiry()))
	ok, rule := sl.MatchesStandingRule("exact", "network_egress", "api.github.com")
	if !ok || rule == nil {
		t.Error("expected exact match")
	}
}

func TestMatchesStandingRule_WildcardDomain_MatchesSingleLevel(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("wc", makeRule("network_egress", "*.github.com", futureExpiry()))
	ok, _ := sl.MatchesStandingRule("wc", "network_egress", "api.github.com")
	if !ok {
		t.Error("*.github.com should match api.github.com")
	}
}

func TestMatchesStandingRule_WildcardDomain_NoMatchMultiLevel(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("wc-multi", makeRule("network_egress", "*.github.com", futureExpiry()))
	ok, _ := sl.MatchesStandingRule("wc-multi", "network_egress", "evil.api.github.com")
	if ok {
		t.Error("*.github.com must NOT match evil.api.github.com (multi-level)")
	}
}

func TestMatchesStandingRule_WildcardDomain_MatchesExactBase(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("wc-base", makeRule("network_egress", "*.github.com", futureExpiry()))
	ok, _ := sl.MatchesStandingRule("wc-base", "network_egress", "github.com")
	if !ok {
		t.Error("*.github.com should match exact base github.com")
	}
}

func TestMatchesStandingRule_PathWildcard_MatchesRecursive(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("path", makeRule("file_write", "/tmp/**", futureExpiry()))
	for _, res := range []string{"/tmp/foo", "/tmp/a/b/c", "/tmp/"} {
		ok, _ := sl.MatchesStandingRule("path", "file_write", res)
		if !ok {
			t.Errorf("/tmp/** should match %q", res)
		}
	}
}

func TestMatchesStandingRule_PathWildcard_NoMatchDifferentPrefix(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("path-no", makeRule("file_write", "/tmp/**", futureExpiry()))
	ok, _ := sl.MatchesStandingRule("path-no", "file_write", "/etc/passwd")
	if ok {
		t.Error("/tmp/** must not match /etc/passwd")
	}
}

func TestMatchesStandingRule_ExpiredRule_NoMatch(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("expired", makeRule("network_egress", "*.github.com", pastExpiry()))
	ok, _ := sl.MatchesStandingRule("expired", "network_egress", "api.github.com")
	if ok {
		t.Error("expired rule must not match")
	}
}

func TestMatchesStandingRule_EffectMismatch_NoMatch(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("eff-mismatch", makeRule("network_egress", "*.github.com", futureExpiry()))
	ok, _ := sl.MatchesStandingRule("eff-mismatch", "content_publish", "api.github.com")
	if ok {
		t.Error("effect mismatch must not match")
	}
}

func TestMatchesStandingRule_TrailingDotNormalized(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("trailing", makeRule("network_egress", "*.github.com", futureExpiry()))
	// Resource with trailing dot (valid DNS)
	ok, _ := sl.MatchesStandingRule("trailing", "network_egress", "api.github.com.")
	if !ok {
		t.Error("trailing dot in resource should be normalized and match *.github.com")
	}
}

func TestMatchesStandingRule_CaseInsensitive(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("case", makeRule("network_egress", "*.GitHub.com", futureExpiry()))
	ok, _ := sl.MatchesStandingRule("case", "network_egress", "API.GITHUB.COM")
	if !ok {
		t.Error("matching should be case-insensitive")
	}
}

func TestMatchesStandingRule_ZeroExpiresAt_NeverExpires(t *testing.T) {
	sl := newSL()
	rule := makeRule("network_egress", "*.github.com", time.Time{}) // zero = never expires
	sl.AddStandingRule("no-expiry", rule)
	ok, _ := sl.MatchesStandingRule("no-expiry", "network_egress", "api.github.com")
	if !ok {
		t.Error("zero ExpiresAt should never expire")
	}
}

// ---- PruneExpiredRules ----

func TestPruneExpiredRules_RemovesExpired(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("prune", makeRule("network_egress", "*.expired.com", pastExpiry()))
	sl.AddStandingRule("prune", makeRule("network_egress", "*.valid.com", futureExpiry()))

	sl.PruneExpiredRules()

	snap := sl.Snapshot("prune")
	if len(snap.StandingRules) != 1 {
		t.Errorf("expected 1 rule after prune, got %d", len(snap.StandingRules))
	}
	if snap.StandingRules[0].ResourcePattern != "*.valid.com" {
		t.Errorf("unexpected remaining rule: %s", snap.StandingRules[0].ResourcePattern)
	}
}

func TestPruneExpiredRules_DemotesApprovalStateWhenNoRulesRemain(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("demote", makeRule("network_egress", "*.expired.com", pastExpiry()))

	sl.PruneExpiredRules()

	snap := sl.Snapshot("demote")
	if snap.ApprovalState != ApprovalNone {
		t.Errorf("expected ApprovalNone after all rules expire, got %d", snap.ApprovalState)
	}
}

func TestPruneExpiredRules_DoesNotDemoteSessionGranted(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("no-demote-sg", makeRule("network_egress", "*.expired.com", pastExpiry()))
	sl.SetApprovalState("no-demote-sg", ApprovalSessionGranted)

	sl.PruneExpiredRules()

	snap := sl.Snapshot("no-demote-sg")
	if snap.ApprovalState != ApprovalSessionGranted {
		t.Errorf("PruneExpiredRules must not demote SessionGranted, got %d", snap.ApprovalState)
	}
}

func TestPruneExpiredRules_KeepsNonExpiredRules(t *testing.T) {
	sl := newSL()
	sl.AddStandingRule("keep", makeRule("network_egress", "*.valid.com", futureExpiry()))
	sl.AddStandingRule("keep", makeRule("file_write", "/tmp/**", futureExpiry()))

	sl.PruneExpiredRules()

	snap := sl.Snapshot("keep")
	if len(snap.StandingRules) != 2 {
		t.Errorf("expected 2 rules to remain, got %d", len(snap.StandingRules))
	}
	if snap.ApprovalState != ApprovalStandingRule {
		t.Errorf("ApprovalState should remain StandingRule, got %d", snap.ApprovalState)
	}
}

// ---- matchesPattern unit tests ----

func TestMatchesPattern_ExactMatch(t *testing.T) {
	if !matchesPattern("api.github.com", "api.github.com") {
		t.Error("exact strings must match")
	}
	if matchesPattern("api.github.com", "other.github.com") {
		t.Error("different exact strings must not match")
	}
}

func TestMatchesPattern_WildcardDomain_OneLevel(t *testing.T) {
	if !matchesPattern("*.github.com", "api.github.com") {
		t.Error("*.github.com should match api.github.com")
	}
}

func TestMatchesPattern_WildcardDomain_TwoLevels_NoMatch(t *testing.T) {
	if matchesPattern("*.github.com", "evil.api.github.com") {
		t.Error("*.github.com must not match evil.api.github.com")
	}
}

func TestMatchesPattern_WildcardDomain_ExactBase(t *testing.T) {
	if !matchesPattern("*.github.com", "github.com") {
		t.Error("*.github.com should match exact base github.com")
	}
}

func TestMatchesPattern_PathDoubleWildcard_Recursive(t *testing.T) {
	cases := []string{"/tmp/foo", "/tmp/foo/bar", "/tmp/a/b/c"}
	for _, c := range cases {
		if !matchesPattern("/tmp/**", c) {
			t.Errorf("/tmp/** should match %q", c)
		}
	}
}

func TestMatchesPattern_CaseInsensitive_ViaMatchesStandingRule(t *testing.T) {
	// matchesPattern itself operates on pre-lowercased inputs.
	// Case insensitivity is enforced by MatchesStandingRule before calling matchesPattern.
	if !matchesPattern("*.github.com", "api.github.com") {
		t.Error("lowercased inputs should match")
	}
}
