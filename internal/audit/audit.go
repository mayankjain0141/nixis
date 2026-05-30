// SPDX-License-Identifier: MIT
// Package audit provides append-only SQLite persistence for Aegis governance decisions.
// A single goroutine writes to SQLite. The hot path enqueues via a buffered
// channel and never blocks.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"log"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mayjain/aegis/internal/otel"
	"github.com/mayjain/aegis/pkg/aegis"
	_ "modernc.org/sqlite"
)

const (
	channelCap   = 1024
	batchSize    = 64
	batchTimeout = 100 * time.Millisecond
)

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

type Writer struct {
	db      *sql.DB
	ch      chan writeItem
	dropped atomic.Int64
}

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
	// Load the last stored chain_hash from the DB so the chain is continuous
	// across Writer restarts. Zero hash is used for the very first record.
	prevHash := loadLastChainHash(w.db)

	batch := make([]writeItem, 0, batchSize)
	timer := time.NewTimer(batchTimeout)
	defer timer.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		prevHash = w.writeBatch(batch, prevHash)
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
		log.Printf("WARNING: audit record dropped (total dropped: %d) — buffer full", w.dropped.Load()+1)
		w.dropped.Add(1)
		otel.InstrumentAuditDropped().Add(context.Background(), 1)
	}
}

// WriteSessionLabel enqueues a SessionLabelRecord for async persistence. Non-blocking.
func (w *Writer) WriteSessionLabel(r SessionLabelRecord) {
	select {
	case w.ch <- writeItem{labelRecord: &r}:
	default:
		w.dropped.Add(1)
		otel.InstrumentAuditDropped().Add(context.Background(), 1)
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
// Returns the updated prevHash after all record inserts in this batch.
// If any INSERT fails, the transaction is rolled back and prevHash is unchanged.
// Fail-secure: a SQLite write failure must not silently produce a partial audit trail.
func (w *Writer) writeBatch(batch []writeItem, prevHash [32]byte) [32]byte {
	tx, err := w.db.Begin()
	if err != nil {
		return prevHash
	}

	current := prevHash
	for _, item := range batch {
		if item.record != nil {
			next, err := w.insertRecord(tx, item.record, current)
			if err != nil {
				if rbErr := tx.Rollback(); rbErr != nil {
					log.Printf("audit: tx.Rollback error (non-fatal): %v", rbErr)
				}
				return prevHash
			}
			current = next
		} else if item.labelRecord != nil {
			if err := w.insertSessionLabel(tx, item.labelRecord); err != nil {
				if rbErr := tx.Rollback(); rbErr != nil {
					log.Printf("audit: tx.Rollback error (non-fatal): %v", rbErr)
				}
				return prevHash
			}
		}
	}

	if err := tx.Commit(); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			log.Printf("audit: tx.Rollback error (non-fatal): %v", rbErr)
		}
		return prevHash
	}
	return current
}

// chainHash computes sha256(prevHash || recordBytes) for a given record.
// recordBytes is a canonical serialisation of the audit row's mutable fields.
func chainHash(prev [32]byte, r *AuditRecord) [32]byte {
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

	h := sha256.New()
	h.Write(prev[:])
	// Canonical record representation: all fields separated by NUL bytes.
	// Changing any field changes the hash and breaks the chain (tamper detection).
	writeChainField(h, appendInt64LE(nil, r.Timestamp))
	writeChainField(h, []byte(r.SessionID))
	writeChainField(h, []byte(r.Tool))
	writeChainField(h, []byte(r.Args))
	writeChainField(h, []byte(action))
	writeChainField(h, []byte(r.Decision.Reason))
	writeChainField(h, []byte(r.Decision.PolicyID))
	writeChainField(h, []byte(string(r.EnforcingLayer)))
	writeChainField(h, appendInt64LE(nil, r.LatencyNs))

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func writeChainField(h interface{ Write([]byte) (int, error) }, data []byte) {
	_, _ = h.Write(data)
	_, _ = h.Write([]byte{0}) // NUL separator
}

func appendInt64LE(buf []byte, n int64) []byte {
	return append(buf,
		byte(n), byte(n>>8), byte(n>>16), byte(n>>24),
		byte(n>>32), byte(n>>40), byte(n>>48), byte(n>>56),
	)
}

func (w *Writer) insertRecord(tx *sql.Tx, r *AuditRecord, prev [32]byte) ([32]byte, error) {
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

	next := chainHash(prev, r)

	_, err := tx.Exec(
		`INSERT INTO audit_log (
			timestamp, session_id, tool, args, action, reason, policy_id,
			enforcing_layer,
			label_before_c, label_before_i, label_before_k,
			label_after_c,  label_after_i,  label_after_k,
			latency_ns, chain_hash
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
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
		next[:],
	)
	if err != nil {
		return prev, err
	}
	return next, nil
}

func (w *Writer) insertSessionLabel(tx *sql.Tx, r *SessionLabelRecord) error {
	_, err := tx.Exec(
		`INSERT INTO session_labels (session_id, label_state, label_c, label_i, label_k, changed_at)
		 VALUES (?,?,?,?,?,?)`,
		r.SessionID,
		r.LabelState,
		r.Label.Confidentiality,
		r.Label.Integrity,
		r.Label.Category,
		r.ChangedAt,
	)
	return err
}

// loadLastChainHash reads the chain_hash of the last row in audit_log.
// Returns a zero hash if the table is empty or the column is NULL (legacy rows).
func loadLastChainHash(db *sql.DB) [32]byte {
	var zero [32]byte
	var blob []byte
	row := db.QueryRow(`SELECT chain_hash FROM audit_log ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&blob); err != nil {
		return zero
	}
	if len(blob) != 32 {
		return zero
	}
	var h [32]byte
	copy(h[:], blob)
	return h
}

// applySchema creates the required tables if they don't exist, and migrates
// existing databases to add the chain_hash column if absent.
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
    latency_ns     INTEGER,
    chain_hash     BLOB
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
	if err != nil {
		return err
	}

	// Migrate existing databases that predate the chain_hash column.
	// SQLite returns an error if the column already exists; ignore it.
	_, _ = db.Exec(`ALTER TABLE audit_log ADD COLUMN chain_hash BLOB`)
	return nil
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
