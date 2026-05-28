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
