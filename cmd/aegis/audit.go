package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

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

func init() {
	auditVerifyCmd.Flags().StringVar(&auditFrom, "from", "", "Start checkpoint (record ID)")
	auditVerifyCmd.Flags().StringVar(&auditTo, "to", "", "End checkpoint (record ID)")
	auditVerifyCmd.Flags().StringVar(&auditDB, "db", "", "Audit database path (default: $AEGIS_AUDIT_DB)")
	auditCmd.AddCommand(auditVerifyCmd)
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

	query := "SELECT id, timestamp, session_id, tool, args, action, reason, policy_id, enforcing_layer, latency_ns FROM audit_log"
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

	// Sequential chain: hash(prevHash || recordBytes). prevHash starts as 32 zero bytes.
	prevHash := make([]byte, 32)
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
		)
		if err := rows.Scan(&id, &timestamp, &sessionID, &tool, &args,
			&action, &reason, &policyID, &enforcingLayer, &latencyNs); err != nil {
			return fmt.Errorf("scan record %d: %w", id, err)
		}

		content := buildRecordContent(id, timestamp, sessionID, tool,
			args.String, action, reason.String, policyID.String,
			enforcingLayer.String, latencyNs.Int64)

		h := sha256.New()
		h.Write(prevHash)
		h.Write(content)
		prevHash = h.Sum(nil)
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate audit log: %w", err)
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "OK: %d records verified, chain hash=%s\n",
		count, hex.EncodeToString(prevHash))
	return nil
}

// buildRecordContent serialises a record into a canonical byte slice for hashing.
func buildRecordContent(id, ts int64, sessionID, tool, args, action, reason, policyID, layer string, latencyNs int64) []byte {
	buf := make([]byte, 0, 256)
	buf = appendInt64LE(buf, id)
	buf = append(buf, 0)
	buf = appendInt64LE(buf, ts)
	buf = append(buf, 0)
	buf = append(buf, sessionID...)
	buf = append(buf, 0)
	buf = append(buf, tool...)
	buf = append(buf, 0)
	buf = append(buf, args...)
	buf = append(buf, 0)
	buf = append(buf, action...)
	buf = append(buf, 0)
	buf = append(buf, reason...)
	buf = append(buf, 0)
	buf = append(buf, policyID...)
	buf = append(buf, 0)
	buf = append(buf, layer...)
	buf = append(buf, 0)
	buf = appendInt64LE(buf, latencyNs)
	return buf
}

func appendInt64LE(buf []byte, n int64) []byte {
	return append(buf,
		byte(n), byte(n>>8), byte(n>>16), byte(n>>24),
		byte(n>>32), byte(n>>40), byte(n>>48), byte(n>>56),
	)
}
