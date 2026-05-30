// SPDX-License-Identifier: MIT
package daemon

import (
	"time"

	"github.com/mayjain/nixis/internal/audit"
	"github.com/mayjain/nixis/pkg/nixis"
)

func buildAuditRecord(req nixis.CheckRequest, resp nixis.CheckResponse) audit.AuditRecord {
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
