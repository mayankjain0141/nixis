package aegis

import "encoding/json"

// Action is the verdict type. Zero value MUST be ActionDeny (INV-001).
type Action int

const (
	ActionDeny Action = iota // 0 — zero value is DENY (INV-001)
	ActionAllow
	ActionRequireApproval // wire: "require_approval"
	ActionAudit           // wire: "audit"
)

func (a Action) MarshalJSON() ([]byte, error) {
	switch a {
	case ActionDeny:
		return json.Marshal("deny")
	case ActionAllow:
		return json.Marshal("allow")
	case ActionRequireApproval:
		return json.Marshal("require_approval")
	case ActionAudit:
		return json.Marshal("audit")
	default:
		return json.Marshal("deny")
	}
}

func (a *Action) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "deny":
		*a = ActionDeny
	case "allow":
		*a = ActionAllow
	case "require_approval":
		*a = ActionRequireApproval
	case "audit":
		*a = ActionAudit
	default:
		*a = ActionDeny
	}
	return nil
}

// SecurityLabel is the lattice label. Zero value = minimum privilege (INV-002).
type SecurityLabel struct {
	Confidentiality uint16 // Bell-LaPadula confidentiality level; 0 = public
	Integrity       uint16 // Biba integrity level; 0 = untrusted
	Category        uint32 // compartment bitmask (ADR-016); 0 = no compartment
}

// EnforcingLayer identifies which evaluation layer produced the decision.
type EnforcingLayer string

const (
	EnforcingLayerCEL        EnforcingLayer = "cel"
	EnforcingLayerIFC        EnforcingLayer = "ifc"
	EnforcingLayerDelegation EnforcingLayer = "delegation"
	EnforcingLayerAdapter    EnforcingLayer = "adapter"
	EnforcingLayerSecretScan EnforcingLayer = "secret-scan"
)

// DelegationRef is a reference in an authority chain.
type DelegationRef struct {
	TokenID string
	Issuer  string
	// DeclassificationGate is non-empty when this token grants declassification authority.
	// When set, AuditRef must also be non-empty — the audit trail proves the declassification
	// was reviewed and approved before the token was issued.
	DeclassificationGate string
	// AuditRef is the audit trail reference for tokens that carry a DeclassificationGate.
	// Validation rejects any token with a non-empty DeclassificationGate and empty AuditRef.
	AuditRef string
}

// CheckRequest is the evaluation input.
type CheckRequest struct {
	Tool           string          // exact tool name as declared by the hook (e.g. "Bash", "Write")
	Args           json.RawMessage // tool arguments; only sha256:<hex> is stored in audit (INV-012)
	SessionID      string          // stable session identifier propagated from the hook
	SecurityLabel  SecurityLabel   // caller's current lattice label at request time
	AuthorityChain []DelegationRef // delegation chain from session root to caller; may be empty
	Nonce          [16]byte        // replay-prevention nonce; must be unique per request
	Timestamp      int64           // Unix nanoseconds at hook call site
}

// Decision is the authorization verdict.
type Decision struct {
	Action   Action        // enforcement action; zero value is Deny (INV-001)
	Reason   string        // human-readable explanation for the action
	PolicyID string        // policy that produced this verdict; empty if no policy matched
	Labels   SecurityLabel // resultant label after evaluation (scalar per IFC-001 / ADR-013)
}

// Annotation is supplemental information attached to a CheckResponse.
type Annotation struct {
	Key   string // annotation identifier (e.g. "policy.match", "secret.type")
	Value string // annotation payload; format is annotation-type specific
}

// CheckResponse is the evaluation output.
type CheckResponse struct {
	Decision             Decision       // authorization verdict including action and labels
	Annotations          []Annotation   // supplemental metadata attached by the evaluating layer
	LatencyNs            int64          // wall-clock evaluation duration in nanoseconds
	EnforcingLayer       EnforcingLayer // layer that produced the decision (cel, ifc, delegation, …)
	PolicySourceLocation string         // source file and line of the matched policy rule; empty if no match
	ThreatSeverity       string         // threat severity hint ("low", "medium", "high", "critical"); empty if not applicable
}

// MaxMessageSize is enforced at the framing layer (WS-07).
const MaxMessageSize = 2 * 1024 * 1024
