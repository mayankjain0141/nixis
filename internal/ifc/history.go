// SPDX-License-Identifier: MIT
package ifc

import (
	"database/sql"
	"log"
	"time"

	_ "modernc.org/sqlite"
)

// TaintRecord represents a single taint event in history.
type TaintRecord struct {
	SessionID string
	Resource  string
	Category  uint32
	TaintedAt time.Time
}

// TaintHistory provides cross-session taint forensics via SQLite persistence.
// A session that accessed critical credentials should remain "suspicious" even
// if the session is GC'd and a new one starts.
type TaintHistory struct {
	db *sql.DB
}

// NewTaintHistory opens (or creates) the taint history database at dbPath.
// The dbPath should be a dedicated file, NOT the audit database.
//
// Sets PRAGMA journal_mode=WAL and PRAGMA busy_timeout=1000 to prevent
// SQLITE_BUSY under concurrency.
func NewTaintHistory(dbPath string) (*TaintHistory, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec("PRAGMA busy_timeout=1000"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if _, err := db.Exec("PRAGMA synchronous=NORMAL"); err != nil {
		_ = db.Close()
		return nil, err
	}

	if err := applyTaintSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &TaintHistory{db: db}, nil
}

func applyTaintSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS taint_history (
    session_id TEXT NOT NULL,
    resource   TEXT NOT NULL,
    category   INTEGER NOT NULL,
    tainted_at INTEGER NOT NULL,
    PRIMARY KEY (session_id, resource)
);

CREATE INDEX IF NOT EXISTS idx_taint_by_session ON taint_history(session_id, tainted_at DESC);
`)
	return err
}

// Record persists a taint event. Upserts: if the same session+resource already
// exists, updates category and tainted_at.
func (h *TaintHistory) Record(sessionID, resource string, category uint32) error {
	_, err := h.db.Exec(`
INSERT INTO taint_history (session_id, resource, category, tainted_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(session_id, resource) DO UPDATE SET
    category = excluded.category,
    tainted_at = excluded.tainted_at`,
		sessionID, resource, category, time.Now().Unix(),
	)
	if err != nil {
		log.Printf("taint_history: record error session=%s resource=%s: %v", sessionID, resource, err)
	}
	return err
}

// RecentFor returns taint records for a session within the given duration.
// Used on session init to check if pre-tainting is needed.
func (h *TaintHistory) RecentFor(sessionID string, since time.Duration) ([]TaintRecord, error) {
	threshold := time.Now().Add(-since).Unix()
	rows, err := h.db.Query(`
SELECT session_id, resource, category, tainted_at
FROM taint_history
WHERE session_id = ? AND tainted_at >= ?
ORDER BY tainted_at DESC`,
		sessionID, threshold,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []TaintRecord
	for rows.Next() {
		var r TaintRecord
		var ts int64
		if err := rows.Scan(&r.SessionID, &r.Resource, &r.Category, &ts); err != nil {
			return nil, err
		}
		r.TaintedAt = time.Unix(ts, 0)
		records = append(records, r)
	}
	return records, rows.Err()
}

// PruneOlderThan removes taint records older than the given duration.
// Returns the number of rows deleted.
// Called periodically by daemon maintenance goroutine.
func (h *TaintHistory) PruneOlderThan(age time.Duration) (int64, error) {
	threshold := time.Now().Add(-age).Unix()
	result, err := h.db.Exec(`DELETE FROM taint_history WHERE tainted_at < ?`, threshold)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// Close closes the underlying database.
func (h *TaintHistory) Close() error {
	return h.db.Close()
}
