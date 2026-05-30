// SPDX-License-Identifier: MIT
package ifc

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewTaintHistory_CreatesDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "taint_history.db")

	h, err := NewTaintHistory(dbPath)
	if err != nil {
		t.Fatalf("NewTaintHistory: %v", err)
	}
	defer h.Close()

	if _, err := os.Stat(dbPath); err != nil {
		t.Errorf("database file not created: %v", err)
	}
}

func TestTaintHistory_Record_Persists(t *testing.T) {
	h := newTestHistory(t)

	if err := h.Record("sess-1", "/etc/shadow", 1); err != nil {
		t.Fatalf("Record: %v", err)
	}

	records, err := h.RecentFor("sess-1", time.Hour)
	if err != nil {
		t.Fatalf("RecentFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	if records[0].Resource != "/etc/shadow" {
		t.Errorf("resource = %q, want /etc/shadow", records[0].Resource)
	}
	if records[0].Category != 1 {
		t.Errorf("category = %d, want 1", records[0].Category)
	}
}

func TestTaintHistory_Record_Upserts(t *testing.T) {
	h := newTestHistory(t)

	if err := h.Record("sess-1", "/etc/shadow", 1); err != nil {
		t.Fatalf("first Record: %v", err)
	}
	if err := h.Record("sess-1", "/etc/shadow", 3); err != nil {
		t.Fatalf("second Record (upsert): %v", err)
	}

	records, err := h.RecentFor("sess-1", time.Hour)
	if err != nil {
		t.Fatalf("RecentFor: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record after upsert, got %d", len(records))
	}
	if records[0].Category != 3 {
		t.Errorf("category after upsert = %d, want 3", records[0].Category)
	}
}

func TestTaintHistory_RecentFor_FiltersOldRecords(t *testing.T) {
	h := newTestHistory(t)

	// Insert a record with a tainted_at far in the past
	_, err := h.db.Exec(
		`INSERT INTO taint_history (session_id, resource, category, tainted_at) VALUES (?,?,?,?)`,
		"sess-old", "/etc/passwd", 1, time.Now().Add(-48*time.Hour).Unix(),
	)
	if err != nil {
		t.Fatalf("insert old record: %v", err)
	}

	records, err := h.RecentFor("sess-old", time.Hour)
	if err != nil {
		t.Fatalf("RecentFor: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("want 0 records for old session, got %d", len(records))
	}
}

func TestTaintHistory_RecentFor_ReturnsEmptyForUnknownSession(t *testing.T) {
	h := newTestHistory(t)

	records, err := h.RecentFor("no-such-session", time.Hour)
	if err != nil {
		t.Fatalf("RecentFor: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("want 0 records, got %d", len(records))
	}
}

func TestTaintHistory_RecentFor_MultipleRecords(t *testing.T) {
	h := newTestHistory(t)

	resources := []string{"/etc/shadow", "~/.ssh/id_rsa", "~/.aws/credentials"}
	for _, r := range resources {
		if err := h.Record("sess-multi", r, 1); err != nil {
			t.Fatalf("Record %s: %v", r, err)
		}
	}

	records, err := h.RecentFor("sess-multi", time.Hour)
	if err != nil {
		t.Fatalf("RecentFor: %v", err)
	}
	if len(records) != len(resources) {
		t.Errorf("want %d records, got %d", len(resources), len(records))
	}
}

func TestTaintHistory_PruneOlderThan_RemovesOldRecords(t *testing.T) {
	h := newTestHistory(t)

	// Insert two old records
	for _, res := range []string{"/old1", "/old2"} {
		_, err := h.db.Exec(
			`INSERT INTO taint_history (session_id, resource, category, tainted_at) VALUES (?,?,?,?)`,
			"sess-prune", res, 1, time.Now().Add(-48*time.Hour).Unix(),
		)
		if err != nil {
			t.Fatalf("insert old record: %v", err)
		}
	}

	// Insert one recent record
	if err := h.Record("sess-prune", "/recent", 1); err != nil {
		t.Fatalf("Record recent: %v", err)
	}

	pruned, err := h.PruneOlderThan(time.Hour)
	if err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	if pruned != 2 {
		t.Errorf("want 2 pruned, got %d", pruned)
	}

	// Recent record must still be there
	records, err := h.RecentFor("sess-prune", time.Hour)
	if err != nil {
		t.Fatalf("RecentFor after prune: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("want 1 record after prune, got %d", len(records))
	}
}

func TestTaintHistory_PruneOlderThan_KeepsRecentRecords(t *testing.T) {
	h := newTestHistory(t)

	if err := h.Record("sess-keep", "/etc/shadow", 1); err != nil {
		t.Fatalf("Record: %v", err)
	}

	pruned, err := h.PruneOlderThan(time.Hour)
	if err != nil {
		t.Fatalf("PruneOlderThan: %v", err)
	}
	if pruned != 0 {
		t.Errorf("want 0 pruned (record is recent), got %d", pruned)
	}

	records, err := h.RecentFor("sess-keep", time.Hour)
	if err != nil {
		t.Fatalf("RecentFor: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("want 1 record to remain, got %d", len(records))
	}
}

func TestTaintHistory_Close_NoPanic(t *testing.T) {
	h := newTestHistory(t)

	if err := h.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	// Second close: underlying sql.DB.Close is safe to call multiple times
	// (returns error but does not panic)
	_ = h.Close()
}

func TestTaintHistory_WALMode_Enabled(t *testing.T) {
	h := newTestHistory(t)

	var mode string
	if err := h.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("journal_mode = %q, want wal", mode)
	}
}

func TestTaintHistory_SessionIsolation(t *testing.T) {
	h := newTestHistory(t)

	if err := h.Record("sess-a", "/etc/shadow", 1); err != nil {
		t.Fatalf("Record sess-a: %v", err)
	}
	if err := h.Record("sess-b", "/etc/shadow", 2); err != nil {
		t.Fatalf("Record sess-b: %v", err)
	}

	aRecords, err := h.RecentFor("sess-a", time.Hour)
	if err != nil {
		t.Fatalf("RecentFor sess-a: %v", err)
	}
	bRecords, err := h.RecentFor("sess-b", time.Hour)
	if err != nil {
		t.Fatalf("RecentFor sess-b: %v", err)
	}

	if len(aRecords) != 1 || aRecords[0].Category != 1 {
		t.Errorf("sess-a: want 1 record with category 1, got %v", aRecords)
	}
	if len(bRecords) != 1 || bRecords[0].Category != 2 {
		t.Errorf("sess-b: want 1 record with category 2, got %v", bRecords)
	}
}

// newTestHistory creates a TaintHistory backed by a temp file and registers cleanup.
func newTestHistory(t *testing.T) *TaintHistory {
	t.Helper()
	dir := t.TempDir()
	h, err := NewTaintHistory(filepath.Join(dir, "taint_history.db"))
	if err != nil {
		t.Fatalf("NewTaintHistory: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}
