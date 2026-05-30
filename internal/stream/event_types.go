// SPDX-License-Identifier: MIT
package stream

// validEventTypes is the set of 12 canonical wire event types.
// No other type may be emitted (STREAMING_PROTOCOL.md §4.1).
var validEventTypes = map[string]bool{
	"policy.evaluated":   true,
	"policy.denied":      true,
	"delegation.created": true,
	"delegation.revoked": true,
	"delegation.expired": true,
	"audit.checkpoint":   true,
	"stream.heartbeat":   true,
	"bundle.activated":   true,
	"system.error":       true,
	"label.escalated":    true,
	"secret.detected":    true,
	"mcp.tool_drift":     true,
}

// normalizeEventType maps internal aegis event type strings (from pkg/aegis constants)
// to the 12 canonical wire types. Unknown types are mapped to "system.error".
func normalizeEventType(internal string) string {
	switch internal {
	case "policy.evaluated", "decision":
		return "policy.evaluated"
	case "policy.denied":
		return "policy.denied"
	case "delegation.created":
		return "delegation.created"
	case "delegation.revoked":
		return "delegation.revoked"
	case "delegation.expired":
		return "delegation.expired"
	case "audit.checkpoint":
		return "audit.checkpoint"
	case "stream.heartbeat":
		return "stream.heartbeat"
	case "bundle.activated":
		return "bundle.activated"
	case "system.error":
		return "system.error"
	case "label.escalated", "label.tainted":
		return "label.escalated"
	case "secret.detected", "secret.found":
		return "secret.detected"
	case "mcp.tool_drift":
		return "mcp.tool_drift"
	default:
		return "system.error"
	}
}
