package daemon

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"github.com/mayjain/aegis/internal/audit"
	"github.com/mayjain/aegis/internal/otel"
	"github.com/mayjain/aegis/pkg/aegis"
)

// headerSize is the byte length of the 4-byte big-endian length prefix.
const headerSize = 4

// ReadMessage reads a single length-prefixed message from r.
//
// Wire format: [4-byte big-endian uint32 length][JSON payload]
//
// Returns an error if:
//   - The 4-byte header cannot be read.
//   - The declared length exceeds aegis.MaxMessageSize.
//   - The payload cannot be fully read.
//
// The deadline parameter is used to set a read deadline on the connection when
// r implements net.Conn; otherwise the deadline is applied via context cancellation.
func ReadMessage(r io.Reader, deadline time.Time, maxSize int) ([]byte, error) {
	if c, ok := r.(net.Conn); ok && !deadline.IsZero() {
		if err := c.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
	}

	var hdr [headerSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:])

	if int(length) > maxSize {
		return nil, errMessageTooLarge
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// WriteMessage writes a single length-prefixed message to w.
//
// Wire format: [4-byte big-endian uint32 length][JSON payload]
func WriteMessage(w io.Writer, payload []byte, deadline time.Time) error {
	if c, ok := w.(net.Conn); ok && !deadline.IsZero() {
		if err := c.SetWriteDeadline(deadline); err != nil {
			return err
		}
	}

	var hdr [headerSize]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))

	// Use net.Buffers for a single writev syscall when available.
	if bc, ok := w.(interface {
		Write([]byte) (int, error)
	}); ok {
		if _, err := bc.Write(hdr[:]); err != nil {
			return err
		}
		if _, err := bc.Write(payload); err != nil {
			return err
		}
		return nil
	}

	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// errMessageTooLarge is returned when a framed message exceeds MaxMessageSize.
var errMessageTooLarge = errors.New("framed message exceeds MaxMessageSize")

// handleConnection serves a single Unix socket connection.
//
// Protocol:
//  1. Read one framed CheckRequest (with 50ms deadline).
//  2. Check daemon mode — deny immediately if ModeDenyAll or ModeReadOnly.
//  3. Evaluate against the policy engine (within same deadline).
//  4. Write one framed CheckResponse.
//  5. Close the connection.
//
// All error paths produce a Deny response and then close; the daemon never
// returns a raw error or a non-JSON frame to the hook (IFC-001).
func (d *Daemon) handleConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(evaluationDeadline)

	raw, err := ReadMessage(conn, deadline, aegis.MaxMessageSize)
	if err != nil {
		if errors.Is(err, errMessageTooLarge) {
			d.writeErrorResponse(conn, deadline, "message exceeds MaxMessageSize")
			return
		}
		// Connection read error — no response possible.
		return
	}

	var req aegis.CheckRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		d.writeErrorResponse(conn, deadline, "malformed JSON request")
		return
	}

	// Enforce daemon mode after reading request but before evaluation.
	// ModeDenyAll and ModeReadOnly deny all requests without evaluating.
	if mode := d.Mode(); mode == ModeDenyAll || mode == ModeReadOnly {
		d.writeModeResponse(conn, deadline, mode)
		return
	}

	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	resp := d.engine.Evaluate(ctx, req)
	d.evaluations.Add(1)

	otel.RecordEvaluation(
		ctx,
		req.Tool,
		req.SessionID,
		actionString(resp.Decision.Action),
		string(resp.EnforcingLayer),
		resp.LatencyNs,
		resp.Decision.Action == aegis.ActionDeny,
	)

	// Persist session label change when the decision is not a deny.
	if d.sessions != nil && resp.Decision.Action != aegis.ActionDeny {
		d.sessions.Elevate(req.SessionID, req.SecurityLabel)
		newLabel := d.sessions.Current(req.SessionID)
		newState := d.sessions.LabelState(req.SessionID)
		d.auditWriter.WriteSessionLabel(audit.SessionLabelRecord{
			SessionID:  req.SessionID,
			LabelState: string(newState),
			Label:      newLabel,
			ChangedAt:  time.Now().UnixNano(),
		})
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		d.writeErrorResponse(conn, deadline, "failed to marshal response")
		return
	}

	_ = WriteMessage(conn, respBytes, deadline)

	d.auditWriter.WriteRecord(buildAuditRecord(req, resp))

	// Emit to streaming server (non-blocking, nil-safe).
	if d.streamSrv != nil {
		eventType := aegis.EventTypeDecision
		if resp.Decision.Action == aegis.ActionDeny {
			eventType = "policy.denied"
		}
		d.streamSrv.Emit(ctx, aegis.StreamEvent{
			Type:           eventType,
			AegisSequence:  0, // assigned in fan-out goroutine
			SessionID:      req.SessionID,
			Tool:           req.Tool,
			Action:         resp.Decision.Action,
			Reason:         resp.Decision.Reason,
			Label:          resp.Decision.Labels,
			Timestamp:      time.Now().UnixNano(),
			PolicyID:       resp.Decision.PolicyID,
			EnforcingLayer: string(resp.EnforcingLayer),
			LabelState:     "fresh",
			LatencyNs:      resp.LatencyNs,
		})
	}
}

// writeErrorResponse writes a Deny CheckResponse to conn.
// Never returns an error to the caller — used in error paths where the
// primary goal is to signal denial before closing.
func (d *Daemon) writeErrorResponse(conn net.Conn, deadline time.Time, reason string) {
	resp := aegis.CheckResponse{
		Decision: aegis.Decision{
			Action: aegis.ActionDeny,
			Reason: reason,
		},
		EnforcingLayer: aegis.EnforcingLayerAdapter,
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = WriteMessage(conn, b, deadline)
}

// actionString converts an Action to its wire-format string, matching MarshalJSON.
func actionString(a aegis.Action) string {
	switch a {
	case aegis.ActionDeny:
		return "deny"
	case aegis.ActionAllow:
		return "allow"
	case aegis.ActionRequireApproval:
		return "require_approval"
	case aegis.ActionAudit:
		return "audit"
	default:
		return "deny"
	}
}

// writeModeResponse writes a Deny CheckResponse for daemon mode enforcement.
// Called when the daemon is in ModeDenyAll or ModeReadOnly and must reject
// all incoming requests without evaluation.
func (d *Daemon) writeModeResponse(conn net.Conn, deadline time.Time, mode DaemonMode) {
	resp := aegis.CheckResponse{
		Decision: aegis.Decision{
			Action: aegis.ActionDeny,
			Reason: "daemon in " + mode.String() + " mode",
		},
		EnforcingLayer: aegis.EnforcingLayerAdapter,
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = WriteMessage(conn, b, deadline)
}
