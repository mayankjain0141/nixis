// Package audit provides append-only SQLite persistence for Aegis governance decisions.
// A single goroutine writes to SQLite (INV-8). The hot path enqueues via a buffered
// channel and never blocks.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mayjain/aegis/pkg/aegis"
	_ "modernc.org/sqlite"
)

const (
	channelCap   = 1024
	batchSize    = 64
	batchTimeout = 100 * time.Millisecond
)

// AuditRecord is an immutable audit log entry written for every Evaluate() call.
type AuditRecord struct {
	ID             int64 // SQLite ROWID (assigned on write)
	Timestamp      int64 // unix nanos
	SessionID      string
	Tool           string
	Args           json.RawMessage
	Decision       aegis.Decision
	LatencyNs      int64
	PolicyID       string
	EnforcingLayer aegis.EnforcingLayer
	LabelBefore    aegis.SecurityLabel
	LabelAfter     aegis.SecurityLabel
}

// SessionLabelRecord tracks label state transitions per session.
type SessionLabelRecord struct {
	SessionID  string
	LabelState string // "fresh", "escalated", "tainted_by_secret", "declassified"
	Label      aegis.SecurityLabel
	ChangedAt  int64 // unix nanos
}

type writeItem struct {
	record      *AuditRecord
	labelRecord *SessionLabelRecord
}

// Writer is the single-goroutine SQLite audit writer.
type Writer struct {
	db      *sql.DB
	ch      chan writeItem
	dropped atomic.Int64
}

// NewWriter opens (or creates) the SQLite database at dbPath and applies the schema.
func NewWriter(dbPath string) (*Writer, error) {
	db, err := sql.Open("sqlite", dbPath+
		"?_journal_mode=WAL&_synchronous=NORMAL&_busy_timeout=5000"+
		"&_cache_size=-65536&_mmap_size=268435456&_temp_store=MEMORY")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	if err := applySchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return &Writer{
		db: db,
		ch: make(chan writeItem, channelCap),
	}, nil
}

// Start runs the writer goroutine. It blocks until ctx is cancelled, then drains.
// Call this in a goroutine: go w.Start(ctx).
func (w *Writer) Start(ctx context.Context) {
	batch := make([]writeItem, 0, batchSize)
	timer := time.NewTimer(batchTimeout)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		w.writeBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case item := <-w.ch:
			batch = append(batch, item)
			if len(batch) >= batchSize {
				flush()
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(batchTimeout)
			}
		case <-timer.C:
			flush()
			timer.Reset(batchTimeout)
		case <-ctx.Done():
			// Drain remaining items.
			for {
				select {
				case item := <-w.ch:
					batch = append(batch, item)
				default:
					flush()
					return
				}
			}
		}
	}
}

// WriteRecord enqueues an AuditRecord for async persistence. Non-blocking.
// If the channel is full the event is dropped and counted.
func (w *Writer) WriteRecord(r AuditRecord) {
	r.Args = SanitizeArgs(r.Args)
	select {
	case w.ch <- writeItem{record: &r}:
	default:
		w.dropped.Add(1)
	}
}

// WriteSessionLabel enqueues a SessionLabelRecord for async persistence. Non-blocking.
func (w *Writer) WriteSessionLabel(r SessionLabelRecord) {
	select {
	case w.ch <- writeItem{labelRecord: &r}:
	default:
		w.dropped.Add(1)
	}
}

// Dropped returns the total number of events dropped due to a full channel.
func (w *Writer) Dropped() int64 {
	return w.dropped.Load()
}

// Close closes the underlying database. Call after Start returns.
func (w *Writer) Close() error {
	return w.db.Close()
}

// writeBatch writes a slice of items inside a single transaction.
func (w *Writer) writeBatch(batch []writeItem) {
	tx, err := w.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback() //nolint:errcheck

	for _, item := range batch {
		if item.record != nil {
			w.insertRecord(tx, item.record)
		} else if item.labelRecord != nil {
			w.insertSessionLabel(tx, item.labelRecord)
		}
	}
	tx.Commit() //nolint:errcheck
}

func (w *Writer) insertRecord(tx *sql.Tx, r *AuditRecord) {
	var action string
	switch r.Decision.Action {
	case aegis.ActionDeny:
		action = "deny"
	case aegis.ActionAllow:
		action = "allow"
	case aegis.ActionRequireApproval:
		action = "require_approval"
	case aegis.ActionAudit:
		action = "audit"
	default:
		action = "deny"
	}

	var argsStr string
	if len(r.Args) > 0 {
		argsStr = string(r.Args)
	}

	tx.Exec( //nolint:errcheck
		`INSERT INTO audit_log (
			timestamp, session_id, tool, args, action, reason, policy_id,
			enforcing_layer,
			label_before_c, label_before_i, label_before_k,
			label_after_c,  label_after_i,  label_after_k,
			latency_ns
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.Timestamp,
		r.SessionID,
		r.Tool,
		argsStr,
		action,
		r.Decision.Reason,
		r.Decision.PolicyID,
		string(r.EnforcingLayer),
		r.LabelBefore.Confidentiality,
		r.LabelBefore.Integrity,
		r.LabelBefore.Category,
		r.LabelAfter.Confidentiality,
		r.LabelAfter.Integrity,
		r.LabelAfter.Category,
		r.LatencyNs,
	)
}

func (w *Writer) insertSessionLabel(tx *sql.Tx, r *SessionLabelRecord) {
	tx.Exec( //nolint:errcheck
		`INSERT INTO session_labels (session_id, label_state, label_c, label_i, label_k, changed_at)
		 VALUES (?,?,?,?,?,?)`,
		r.SessionID,
		r.LabelState,
		r.Label.Confidentiality,
		r.Label.Integrity,
		r.Label.Category,
		r.ChangedAt,
	)
}

// applySchema creates the required tables if they don't exist.
// Append-only: no UPDATE or DELETE statements appear anywhere in this package.
func applySchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      INTEGER NOT NULL,
    session_id     TEXT NOT NULL,
    tool           TEXT NOT NULL,
    args           TEXT,
    action         TEXT NOT NULL,
    reason         TEXT,
    policy_id      TEXT,
    enforcing_layer TEXT,
    label_before_c INTEGER,
    label_before_i INTEGER,
    label_before_k INTEGER,
    label_after_c  INTEGER,
    label_after_i  INTEGER,
    label_after_k  INTEGER,
    latency_ns     INTEGER
);

CREATE TABLE IF NOT EXISTS session_labels (
    session_id   TEXT NOT NULL,
    label_state  TEXT NOT NULL,
    label_c      INTEGER,
    label_i      INTEGER,
    label_k      INTEGER,
    changed_at   INTEGER NOT NULL,
    PRIMARY KEY (session_id, changed_at)
);
`)
	return err
}

// SanitizeArgs removes secret values from JSON args before audit logging.
// Fields whose names contain "key", "token", "secret", or "password" are redacted.
// Returns a sanitized copy — does NOT modify the input.
func SanitizeArgs(args json.RawMessage) json.RawMessage {
	if len(args) == 0 {
		return args
	}

	var m map[string]json.RawMessage
	if err := json.Unmarshal(args, &m); err != nil {
		// Not a JSON object; return as-is (could be array or primitive).
		return args
	}

	redacted := false
	for k := range m {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "key") ||
			strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "password") {
			m[k] = json.RawMessage(`"[REDACTED]"`)
			redacted = true
		}
	}

	if !redacted {
		return args
	}

	out, err := json.Marshal(m)
	if err != nil {
		return args
	}
	return out
}
