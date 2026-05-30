// SPDX-License-Identifier: MIT
package daemon

import (
	"time"

	"github.com/mayjain/aegis/internal/audit"
	"github.com/mayjain/aegis/pkg/aegis"
)

func buildAuditRecord(req aegis.CheckRequest, resp aegis.CheckResponse) audit.AuditRecord {
	return audit.AuditRecord{
		Timestamp:      time.Now().UnixNano(),
		SessionID:      req.SessionID,
		Tool:           req.Tool,
		Args:           req.Args,
		Decision:       resp.Decision,
		LatencyNs:      resp.LatencyNs,
		PolicyID:       resp.Decision.PolicyID,
		EnforcingLayer: resp.EnforcingLayer,
	}
}
