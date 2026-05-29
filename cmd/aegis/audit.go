// SPDX-License-Identifier: MIT
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	_ "modernc.org/sqlite"

	"github.com/spf13/cobra"
)

var (
	auditFrom string
	auditTo   string
	auditDB   string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit log operations",
}

var auditVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify chain integrity in the audit database",
	RunE:  runAuditVerify,
}

var (
	auditExportFormat string
	auditExportFrom   string
	auditExportTo     string
	auditExportDB     string
)

var auditExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export audit log records to stdout",
	RunE:  runAuditExport,
}

var (
	auditTailN          int
	auditTailFollow     bool
	auditTailDB         string
	auditTailStreamAddr string
)

var auditTailCmd = &cobra.Command{
	Use:   "tail",
	Short: "Show recent audit log records",
	RunE:  runAuditTail,
}

func init() {
	auditVerifyCmd.Flags().StringVar(&auditFrom, "from", "", "Start checkpoint (record ID)")
	auditVerifyCmd.Flags().StringVar(&auditTo, "to", "", "End checkpoint (record ID)")
	auditVerifyCmd.Flags().StringVar(&auditDB, "db", "", "Audit database path (default: $AEGIS_AUDIT_DB)")
	auditCmd.AddCommand(auditVerifyCmd)

	auditExportCmd.Flags().StringVar(&auditExportFormat, "format", "jsonl", "Output format: jsonl or csv")
	auditExportCmd.Flags().StringVar(&auditExportFrom, "from", "", "Start time (RFC3339 or unix timestamp)")
	auditExportCmd.Flags().StringVar(&auditExportTo, "to", "", "End time (RFC3339 or unix timestamp)")
	auditExportCmd.Flags().StringVar(&auditExportDB, "db", "", "Audit database path (default: $AEGIS_AUDIT_DB)")
	auditCmd.AddCommand(auditExportCmd)

	auditTailCmd.Flags().IntVarP(&auditTailN, "lines", "n", 20, "Number of records to show")
	auditTailCmd.Flags().BoolVarP(&auditTailFollow, "follow", "f", false, "Stream new records via WebSocket")
	auditTailCmd.Flags().StringVar(&auditTailDB, "db", "", "Audit database path (default: $AEGIS_AUDIT_DB)")
	auditTailCmd.Flags().StringVar(&auditTailStreamAddr, "stream-addr", "ws://127.0.0.1:9090/ws", "Daemon WebSocket stream address for --follow")
	auditCmd.AddCommand(auditTailCmd)
}

func resolveAuditDB() string {
	if auditDB != "" {
		return auditDB
	}
	if v := os.Getenv("AEGIS_AUDIT_DB"); v != "" {
		return v
	}
	return ""
}

func runAuditVerify(cmd *cobra.Command, _ []string) error {
	dbPath := resolveAuditDB()
	if dbPath == "" {
		return fmt.Errorf("audit database path not set: use --db or $AEGIS_AUDIT_DB")
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open audit database: %w", err)
	}
	defer func() {
		_ = db.Close()
	}()

	query := `SELECT id, timestamp, session_id, tool, args, action, reason, policy_id,
		enforcing_layer, latency_ns, chain_hash FROM audit_log`
	var queryArgs []interface{}

	switch {
	case auditFrom != "" && auditTo != "":
		fromID, err := strconv.ParseInt(auditFrom, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid --from value: %w", err)
		}
		toID, err := strconv.ParseInt(auditTo, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid --to value: %w", err)
		}
		query += " WHERE id BETWEEN ? AND ?"
		queryArgs = append(queryArgs, fromID, toID)
	case auditFrom != "":
		fromID, err := strconv.ParseInt(auditFrom, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid --from value: %w", err)
		}
		query += " WHERE id >= ?"
		queryArgs = append(queryArgs, fromID)
	case auditTo != "":
		toID, err := strconv.ParseInt(auditTo, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid --to value: %w", err)
		}
		query += " WHERE id <= ?"
		queryArgs = append(queryArgs, toID)
	}

	query += " ORDER BY id ASC"

	rows, err := db.Query(query, queryArgs...)
	if err != nil {
		return fmt.Errorf("query audit log: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	// Verification: for each row, recompute sha256(prevHash || fields) and compare
	// against the stored chain_hash. A mismatch means a field was tampered.
	// Rows with NULL chain_hash (written before this feature) are skipped.
	var prevHash [32]byte
	count := 0

	for rows.Next() {
		var (
			id             int64
			timestamp      int64
			sessionID      string
			tool           string
			args           sql.NullString
			action         string
			reason         sql.NullString
			policyID       sql.NullString
			enforcingLayer sql.NullString
			latencyNs      sql.NullInt64
			storedHash     []byte
		)
		if err := rows.Scan(&id, &timestamp, &sessionID, &tool, &args,
			&action, &reason, &policyID, &enforcingLayer, &latencyNs, &storedHash); err != nil {
			return fmt.Errorf("scan record %d: %w", id, err)
		}

		// Skip rows that predate the chain_hash column (NULL → zero-length blob).
		if len(storedHash) != 32 {
			count++
			continue
		}

		expected := computeChainHash(prevHash, timestamp, sessionID, tool,
			args.String, action, reason.String, policyID.String,
			enforcingLayer.String, latencyNs.Int64)

		if expected != [32]byte(storedHash) {
			return fmt.Errorf("corruption detected at record id=%d: stored hash %s does not match recomputed hash %s",
				id, hex.EncodeToString(storedHash), hex.EncodeToString(expected[:]))
		}

		copy(prevHash[:], storedHash)
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate audit log: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OK: %d records verified, chain hash=%s\n",
		count, hex.EncodeToString(prevHash[:]))
	return nil
}

// computeChainHash replicates the hash logic from internal/audit.chainHash.
// Field ordering and NUL separator MUST stay in sync with that function.
func computeChainHash(prev [32]byte, ts int64, sessionID, tool, args, action, reason, policyID, layer string, latencyNs int64) [32]byte {
	h := sha256.New()
	h.Write(prev[:])
	writeHashField(h, appendInt64LE(nil, ts))
	writeHashField(h, []byte(sessionID))
	writeHashField(h, []byte(tool))
	writeHashField(h, []byte(args))
	writeHashField(h, []byte(action))
	writeHashField(h, []byte(reason))
	writeHashField(h, []byte(policyID))
	writeHashField(h, []byte(layer))
	writeHashField(h, appendInt64LE(nil, latencyNs))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func writeHashField(h interface{ Write([]byte) (int, error) }, data []byte) {
	_, _ = h.Write(data)
	_, _ = h.Write([]byte{0})
}

func appendInt64LE(buf []byte, n int64) []byte {
	return append(buf,
		byte(n), byte(n>>8), byte(n>>16), byte(n>>24),
		byte(n>>32), byte(n>>40), byte(n>>48), byte(n>>56),
	)
}

// auditRow holds a single audit_log row for export/tail.
type auditRow struct {
	ID             int64  `json:"id"`
	Timestamp      int64  `json:"ts"`
	SessionID      string `json:"session_id"`
	Tool           string `json:"tool"`
	Action         string `json:"action"`
	Reason         string `json:"reason,omitempty"`
	PolicyID       string `json:"policy_id,omitempty"`
	EnforcingLayer string `json:"enforcing_layer,omitempty"`
	LatencyNs      int64  `json:"latency_ns,omitempty"`
}

// csvHeader returns ordered column headers for CSV export.
var csvHeader = []string{"id", "ts", "session_id", "tool", "action", "reason", "policy_id", "enforcing_layer", "latency_ns"}

func resolveExportDB() string {
	if auditExportDB != "" {
		return auditExportDB
	}
	return resolveAuditDB()
}

func parseMaybeUnixTime(s string) (int64, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("cannot parse %q as RFC3339 or unix timestamp", s)
	}
	return t.UnixNano(), nil
}

func buildExportQuery() (string, []interface{}, error) {
	query := `SELECT id, timestamp, session_id, tool, action, reason, policy_id, enforcing_layer, latency_ns
		FROM audit_log`
	var queryArgs []interface{}
	var conditions []string

	if auditExportFrom != "" {
		ts, err := parseMaybeUnixTime(auditExportFrom)
		if err != nil {
			return "", nil, fmt.Errorf("--from: %w", err)
		}
		conditions = append(conditions, "timestamp >= ?")
		queryArgs = append(queryArgs, ts)
	}
	if auditExportTo != "" {
		ts, err := parseMaybeUnixTime(auditExportTo)
		if err != nil {
			return "", nil, fmt.Errorf("--to: %w", err)
		}
		conditions = append(conditions, "timestamp <= ?")
		queryArgs = append(queryArgs, ts)
	}

	if len(conditions) > 0 {
		query += " WHERE " + conditions[0]
		for _, c := range conditions[1:] {
			query += " AND " + c
		}
	}
	query += " ORDER BY id ASC"
	return query, queryArgs, nil
}

func scanAuditRow(rows *sql.Rows) (auditRow, error) {
	var (
		id             int64
		timestamp      int64
		sessionID      string
		tool           string
		action         string
		reason         sql.NullString
		policyID       sql.NullString
		enforcingLayer sql.NullString
		latencyNs      sql.NullInt64
	)
	if err := rows.Scan(&id, &timestamp, &sessionID, &tool, &action,
		&reason, &policyID, &enforcingLayer, &latencyNs); err != nil {
		return auditRow{}, err
	}
	return auditRow{
		ID:             id,
		Timestamp:      timestamp,
		SessionID:      sessionID,
		Tool:           tool,
		Action:         action,
		Reason:         reason.String,
		PolicyID:       policyID.String,
		EnforcingLayer: enforcingLayer.String,
		LatencyNs:      latencyNs.Int64,
	}, nil
}

func runAuditExport(cmd *cobra.Command, _ []string) error {
	dbPath := resolveExportDB()
	if dbPath == "" {
		return fmt.Errorf("audit database path not set: use --db or $AEGIS_AUDIT_DB")
	}

	if auditExportFormat != "jsonl" && auditExportFormat != "csv" {
		return fmt.Errorf("unsupported format %q: use jsonl or csv", auditExportFormat)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open audit database: %w", err)
	}
	defer func() {
		_ = db.Close()
	}()

	query, queryArgs, err := buildExportQuery()
	if err != nil {
		return err
	}

	rows, err := db.Query(query, queryArgs...)
	if err != nil {
		return fmt.Errorf("query audit log: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	w := bufio.NewWriter(cmd.OutOrStdout())
	defer func() {
		_ = w.Flush()
	}()

	if auditExportFormat == "csv" {
		cw := csv.NewWriter(w)
		if err := cw.Write(csvHeader); err != nil {
			return fmt.Errorf("write CSV header: %w", err)
		}
		for rows.Next() {
			r, err := scanAuditRow(rows)
			if err != nil {
				return fmt.Errorf("scan row: %w", err)
			}
			record := []string{
				strconv.FormatInt(r.ID, 10),
				strconv.FormatInt(r.Timestamp, 10),
				r.SessionID,
				r.Tool,
				r.Action,
				r.Reason,
				r.PolicyID,
				r.EnforcingLayer,
				strconv.FormatInt(r.LatencyNs, 10),
			}
			if err := cw.Write(record); err != nil {
				return fmt.Errorf("write CSV row: %w", err)
			}
		}
		cw.Flush()
		if err := cw.Error(); err != nil {
			return fmt.Errorf("flush CSV: %w", err)
		}
	} else {
		enc := json.NewEncoder(w)
		for rows.Next() {
			r, err := scanAuditRow(rows)
			if err != nil {
				return fmt.Errorf("scan row: %w", err)
			}
			if err := enc.Encode(r); err != nil {
				return fmt.Errorf("encode JSON: %w", err)
			}
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate rows: %w", err)
	}
	return nil
}

func runAuditTail(cmd *cobra.Command, _ []string) error {
	dbPath := auditTailDB
	if dbPath == "" {
		dbPath = resolveAuditDB()
	}
	if dbPath == "" {
		return fmt.Errorf("audit database path not set: use --db or $AEGIS_AUDIT_DB")
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open audit database: %w", err)
	}
	defer func() {
		_ = db.Close()
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	w := bufio.NewWriter(cmd.OutOrStdout())

	if _, err := printLastN(w, db, auditTailN, 0); err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush output: %w", err)
	}

	if !auditTailFollow {
		return nil
	}

	return tailFollow(ctx, w, auditTailStreamAddr)
}

// tailFollow streams audit events from the daemon's WebSocket endpoint.
// It connects to the stream server and prints events whose type begins with "audit.",
// "policy.", or "bundle." — the event types that represent governance decisions.
func tailFollow(ctx context.Context, w *bufio.Writer, addr string) error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}
	conn, _, err := dialer.DialContext(ctx, addr, nil)
	if err != nil {
		return fmt.Errorf("connect to stream at %s: %w", addr, err)
	}
	defer func() {
		_ = conn.Close()
	}()

	enc := json.NewEncoder(w)
	for {
		if ctx.Err() != nil {
			return nil
		}

		// Apply a read deadline so we can check ctx cancellation periodically.
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return fmt.Errorf("set read deadline: %w", err)
		}

		_, msg, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return nil
			}
			// Read deadline expired — loop to check ctx then read again.
			if isTimeoutError(err) {
				continue
			}
			return fmt.Errorf("stream read: %w", err)
		}

		// Parse the envelope to extract the event type.
		var envelope struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(msg, &envelope); err != nil {
			continue
		}

		// Filter for audit-relevant event types.
		if !isAuditEventType(envelope.Type) {
			continue
		}

		// Emit the full CloudEvent envelope as JSONL.
		if err := enc.Encode(json.RawMessage(msg)); err != nil {
			return fmt.Errorf("encode event: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("flush output: %w", err)
		}
	}
}

// isAuditEventType returns true for event types that represent governance decisions.
func isAuditEventType(t string) bool {
	return strings.HasPrefix(t, "audit.") ||
		strings.HasPrefix(t, "policy.") ||
		strings.HasPrefix(t, "bundle.") ||
		t == "label.escalated" ||
		t == "secret.detected"
}

// isTimeoutError reports whether err is a network timeout.
func isTimeoutError(err error) bool {
	type timeoutErr interface {
		Timeout() bool
	}
	if te, ok := err.(timeoutErr); ok {
		return te.Timeout()
	}
	return false
}

func printLastN(w *bufio.Writer, db *sql.DB, n int, afterID int64) (int64, error) {
	query := `SELECT id, timestamp, session_id, tool, action, reason, policy_id, enforcing_layer, latency_ns
		FROM audit_log`
	var args []interface{}
	if afterID > 0 {
		query += " WHERE id > ?"
		args = append(args, afterID)
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, n)

	rows, err := db.Query(query, args...)
	if err != nil {
		return afterID, fmt.Errorf("query tail: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	// Collect in reverse so we can output oldest-first.
	var records []auditRow
	for rows.Next() {
		r, err := scanAuditRow(rows)
		if err != nil {
			return afterID, fmt.Errorf("scan row: %w", err)
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		return afterID, fmt.Errorf("iterate rows: %w", err)
	}

	var maxID int64
	enc := json.NewEncoder(w)
	for i := len(records) - 1; i >= 0; i-- {
		r := records[i]
		if r.ID > maxID {
			maxID = r.ID
		}
		if err := enc.Encode(r); err != nil {
			return afterID, fmt.Errorf("encode row: %w", err)
		}
	}
	if maxID == 0 {
		return afterID, nil
	}
	return maxID, nil
}
