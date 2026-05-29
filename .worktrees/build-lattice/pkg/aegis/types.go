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
	Confidentiality uint16
	Integrity       uint16
	Category        uint32 // uint32 per ADR-016
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
	Tool           string
	Args           json.RawMessage
	SessionID      string
	SecurityLabel  SecurityLabel
	AuthorityChain []DelegationRef
	Nonce          [16]byte
	Timestamp      int64
}

// Decision is the authorization verdict.
type Decision struct {
	Action   Action
	Reason   string
	PolicyID string
	Labels   SecurityLabel // scalar per IFC-001 / ADR-013
}

// Annotation is supplemental information attached to a CheckResponse.
type Annotation struct {
	Key   string
	Value string
}

// CheckResponse is the evaluation output.
type CheckResponse struct {
	Decision             Decision
	Annotations          []Annotation
	LatencyNs            int64
	EnforcingLayer       EnforcingLayer
	PolicySourceLocation string
	ThreatSeverity       string
}

// MaxMessageSize is enforced at the framing layer (WS-07).
const MaxMessageSize = 2 * 1024 * 1024
