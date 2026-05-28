// Package policy implements the top-level governance evaluation pipeline for Aegis.
//
// PolicyEngine implements aegis.Engine with a 5-layer evaluation pipeline:
//  1. Adapter layer:    classify.Classify() → VerdictEntry
//  2. IFC layer:        ifc.Dominates() → deny if session cannot access resource
//  3. CEL layer:        evaluate matching PolicyBindings → first DENY wins
//  4. Secret scan:      secretScanner.ScanBoundary() (MVP-1 stub)
//  5. Delegation:       delegationValidator.Validate() (MVP-1 stub)
//
// Hot path contract: Evaluate() loads the snapshot exactly ONCE at entry. The same
// pointer is passed through the entire call stack. No mid-evaluation reload.
//
// Critical invariants:
//   - INV-001: Zero-value Action is ActionDeny (fail-secure).
//   - INV-005: atomic.Pointer.Store() appears ONCE — in applySnapshot().
//   - INV-006: reloadMu is never held during Evaluate().
//   - INV-007: Failed reload never replaces the snapshot.
package policy

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mayjain/aegis/internal/audit"
	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/classify"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/pkg/aegis"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// BoundaryType identifies the trust boundary for secret scanning.
type BoundaryType uint8

const (
	BoundaryToolArgs BoundaryType = iota
	BoundaryToolResponse
	BoundaryFileContent
)

// Finding is a single detected secret.
type Finding struct {
	Boundary    BoundaryType
	Rule        string
	Category    uint32
	Redacted    string
	StartOffset int
	EndOffset   int
}

// SecretScanner is the interface for secret detection (WS-09).
// MVP-1 uses a stub implementation that always returns no findings.
type SecretScanner interface {
	ScanBoundary(ctx context.Context, content string, boundary BoundaryType) ([]Finding, aegis.SecurityLabel)
	ShouldScan(effects []string, boundary BoundaryType) bool
}

// DelegationValidator is the interface for delegation chain validation (WS-10).
// MVP-1 uses a stub implementation that always succeeds.
type DelegationValidator interface {
	Validate(chain []aegis.DelegationRef, now time.Time) error
}

// classifierInterface abstracts the Classifier for testing (panic injection).
type classifierInterface interface {
	Classify(toolName string) (classify.VerdictEntry, bool)
	ClassifyBash(toolName, commandText string) classify.VerdictEntry
}

// engineSnapshot extends the public aegis.EngineSnapshot with internal evaluation state.
// internal/policy/ owns this type entirely.
type engineSnapshot struct {
	public     aegis.EngineSnapshot
	bindings   []compiledBinding
	programs   *cel.ProgramCache
	classifier *classify.Classifier
	// classifierIntf is used when classifier is nil (test injection).
	classifierIntf classifierInterface
	bindingIdx     bindingIndex
	compiledAt     int64
	sourceHash     [32]byte
}

// compiledBinding pairs a policy binding with its pre-resolved scope key.
type compiledBinding struct {
	binding policy_types.PolicyBinding
	scope   scopeKey
}

// scopeKey is a pre-computed key for O(1) binding lookup.
type scopeKey struct {
	tool    string
	session string
}

// bindingIndex provides O(1) lookup for bindings by tool name.
type bindingIndex struct {
	byTool map[string][]*compiledBinding
	all    []*compiledBinding
}

// snapshotBuilder is the signature for buildSnapshot (injectable for testing).
type snapshotBuilder func(ctx context.Context, bundle *aegis.CompiledBundle, version uint64) (*engineSnapshot, error)

// PolicyEngine is the top-level governance evaluator implementing aegis.Engine.
type PolicyEngine struct {
	snapshot            atomic.Pointer[engineSnapshot]
	reloadMu            sync.Mutex
	sessions            *ifc.SessionLabels
	celEnv              *cel.CELEnvironment
	auditWriter         *audit.Writer
	secretScanner       SecretScanner
	delegationValidator DelegationValidator
	activationBuilder   *cel.ActivationBuilder
	// buildSnapshotFunc is injected for testing failed reload scenarios.
	// If nil, the default buildSnapshot is used.
	buildSnapshotFunc snapshotBuilder
}

// Option configures a PolicyEngine.
type Option func(*PolicyEngine)

// WithAuditWriter sets the audit writer for the engine.
func WithAuditWriter(w *audit.Writer) Option {
	return func(e *PolicyEngine) {
		e.auditWriter = w
	}
}

// WithSecretScanner sets the secret scanner for the engine.
func WithSecretScanner(s SecretScanner) Option {
	return func(e *PolicyEngine) {
		e.secretScanner = s
	}
}

// WithDelegationValidator sets the delegation validator for the engine.
func WithDelegationValidator(v DelegationValidator) Option {
	return func(e *PolicyEngine) {
		e.delegationValidator = v
	}
}

// NewPolicyEngine creates a new PolicyEngine with nil snapshot.
// Evaluate() returns Deny until the first successful Reload() (fail-secure).
func NewPolicyEngine(
	sessions *ifc.SessionLabels,
	celEnv *cel.CELEnvironment,
	opts ...Option,
) *PolicyEngine {
	e := &PolicyEngine{
		sessions:            sessions,
		celEnv:              celEnv,
		secretScanner:       &noopSecretScanner{},
		delegationValidator: &noopDelegationValidator{},
		activationBuilder:   cel.NewActivationBuilder(),
	}
	for _, opt := range opts {
		opt(e)
	}
	cel.SetSessionLabels(sessions)
	return e
}

// Evaluate evaluates a CheckRequest against the current policy snapshot.
//
// Hot path contract:
//   - Snapshot is loaded ONCE at entry and passed through the entire call stack.
//   - If snapshot is nil OR any internal error occurs, returns Decision{Action: ActionDeny}.
//   - On first DENY from any layer, short-circuits and returns immediately.
//   - Never returns an error — failures encode as Deny decisions.
func (e *PolicyEngine) Evaluate(ctx context.Context, req aegis.CheckRequest) aegis.CheckResponse {
	startNs := time.Now().UnixNano()

	snap := e.snapshot.Load()
	if snap == nil {
		return denyResponse("policy engine not initialized", aegis.EnforcingLayerAdapter, startNs)
	}

	return e.evaluateWithSnapshot(ctx, req, snap, startNs)
}

// evaluateWithSnapshot runs the 5-layer pipeline against the given snapshot.
func (e *PolicyEngine) evaluateWithSnapshot(
	ctx context.Context,
	req aegis.CheckRequest,
	snap *engineSnapshot,
	startNs int64,
) (resp aegis.CheckResponse) {
	defer func() {
		if r := recover(); r != nil {
			resp = denyResponse("internal evaluation panic", aegis.EnforcingLayerAdapter, startNs)
		}
	}()

	var commandText string
	if req.Tool == "Bash" {
		if cmd, ok := extractCommandText(req.Args); ok {
			commandText = cmd
		}
	}

	var verdict classify.VerdictEntry
	if commandText != "" && snap.classifier != nil {
		verdict = snap.classifier.ClassifyBash(req.Tool, commandText)
	} else if snap.classifier != nil {
		verdict, _ = snap.classifier.Classify(req.Tool)
	} else if snap.classifierIntf != nil {
		if commandText != "" {
			verdict = snap.classifierIntf.ClassifyBash(req.Tool, commandText)
		} else {
			verdict, _ = snap.classifierIntf.Classify(req.Tool)
		}
	} else {
		verdict = classify.VerdictEntry{
			Classification: "unknown",
			RiskLevel:      classify.RiskHigh,
			AdapterMatch:   false,
		}
	}

	if verdict.RiskLevel == classify.RiskCritical {
		return denyResponseWithVerdict(
			"tool classified as critical risk",
			aegis.EnforcingLayerAdapter,
			startNs,
			verdict,
		)
	}

	sessionLabel := e.sessions.Current(req.SessionID)
	resourceLabel := req.SecurityLabel

	if !ifc.Dominates(sessionLabel, resourceLabel) {
		return denyResponseWithVerdict(
			"IFC dominance check failed: session label does not dominate resource label",
			aegis.EnforcingLayerIFC,
			startNs,
			verdict,
		)
	}

	ceiling := e.sessions.Ceiling(req.SessionID)
	if !ifc.Dominates(ceiling, sessionLabel) {
		return denyResponseWithVerdict(
			"delegation ceiling exceeded",
			aegis.EnforcingLayerDelegation,
			startNs,
			verdict,
		)
	}

	var decodedArgs map[string]any
	if len(req.Args) > 0 {
		if err := json.Unmarshal(req.Args, &decodedArgs); err != nil {
			decodedArgs = nil
		}
	}

	matchedBindings := snap.matchBindings(req.Tool, req.SessionID)
	for _, cb := range matchedBindings {
		prog, ok := snap.programs.Get(cb.binding.TemplateID)
		if !ok {
			continue
		}

		val, err := e.activationBuilder.Evaluate(ctx, prog, req, verdict, decodedArgs)
		if err != nil {
			continue
		}

		if b, ok := val.Value().(bool); ok && !b {
			sourceLocation := snap.programs.SourceLocation(cb.binding.TemplateID)
			return aegis.CheckResponse{
				Decision: aegis.Decision{
					Action:   aegis.ActionDeny,
					Reason:   "CEL policy evaluation returned false",
					PolicyID: cb.binding.TemplateID,
					Labels:   sessionLabel,
				},
				LatencyNs:            time.Now().UnixNano() - startNs,
				EnforcingLayer:       aegis.EnforcingLayerCEL,
				PolicySourceLocation: sourceLocation,
			}
		}
	}

	if e.secretScanner.ShouldScan(verdict.Effects, BoundaryToolArgs) {
		var content string
		if commandText != "" {
			content = commandText
		} else if len(req.Args) > 0 {
			content = string(req.Args)
		}

		if content != "" {
			findings, elevatedLabel := e.secretScanner.ScanBoundary(ctx, content, BoundaryToolArgs)
			if len(findings) > 0 {
				e.sessions.TaintWithSecret(req.SessionID)
				return aegis.CheckResponse{
					Decision: aegis.Decision{
						Action:   aegis.ActionDeny,
						Reason:   "secret detected in tool arguments",
						PolicyID: "builtin:secret-scan",
						Labels:   elevatedLabel,
					},
					LatencyNs:      time.Now().UnixNano() - startNs,
					EnforcingLayer: aegis.EnforcingLayerSecretScan,
					ThreatSeverity: "high",
				}
			}
		}
	}

	if len(req.AuthorityChain) > 0 {
		if err := e.delegationValidator.Validate(req.AuthorityChain, time.Now()); err != nil {
			return denyResponseWithVerdict(
				"delegation chain validation failed",
				aegis.EnforcingLayerDelegation,
				startNs,
				verdict,
			)
		}
	}

	return aegis.CheckResponse{
		Decision: aegis.Decision{
			Action: aegis.ActionAllow,
			Labels: sessionLabel,
		},
		LatencyNs:      time.Now().UnixNano() - startNs,
		EnforcingLayer: aegis.EnforcingLayerAdapter,
	}
}

// Reload atomically swaps the EngineSnapshot.
// INV-005: This is the ONLY method that calls atomic.Pointer.Store() — via applySnapshot().
// INV-006: reloadMu serializes concurrent Reload() calls but is never held during Evaluate().
// INV-007: If any step fails, the existing snapshot continues serving.
func (e *PolicyEngine) Reload(ctx context.Context, bundle *aegis.CompiledBundle) error {
	e.reloadMu.Lock()
	defer e.reloadMu.Unlock()

	prev := e.snapshot.Load()
	nextVersion := uint64(1)
	if prev != nil {
		nextVersion = prev.public.Version + 1
	}

	builder := e.buildSnapshot
	if e.buildSnapshotFunc != nil {
		builder = e.buildSnapshotFunc
	}

	newSnap, err := builder(ctx, bundle, nextVersion)
	if err != nil {
		return err
	}

	e.applySnapshot(newSnap)
	return nil
}

// applySnapshot is the ONLY place atomic.Pointer.Store() is called (INV-005).
func (e *PolicyEngine) applySnapshot(snap *engineSnapshot) {
	e.snapshot.Store(snap)
}

// buildSnapshot constructs a new engineSnapshot from the compiled bundle.
func (e *PolicyEngine) buildSnapshot(
	ctx context.Context,
	bundle *aegis.CompiledBundle,
	version uint64,
) (*engineSnapshot, error) {
	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{
			Version: version,
		},
		compiledAt: time.Now().UnixNano(),
		sourceHash: bundle.Hash,
	}
	return snap, nil
}

// matchBindings returns all bindings that match the given tool and session.
// Scope filtering uses the scopeKey for O(1) lookup when byTool index is populated.
func (s *engineSnapshot) matchBindings(tool, session string) []*compiledBinding {
	if s.bindingIdx.byTool == nil {
		return filterByScope(s.bindingIdx.all, tool, session)
	}

	matches := s.bindingIdx.byTool[tool]
	if len(matches) == 0 {
		return filterByScope(s.bindingIdx.all, tool, session)
	}
	return filterByScope(matches, tool, session)
}

// filterByScope filters bindings by scope key when scope is non-empty.
func filterByScope(bindings []*compiledBinding, tool, session string) []*compiledBinding {
	if len(bindings) == 0 {
		return bindings
	}
	// Fast path: if first binding has empty scope, assume all do (common case).
	if bindings[0].scope.tool == "" && bindings[0].scope.session == "" {
		return bindings
	}
	result := make([]*compiledBinding, 0, len(bindings))
	for _, b := range bindings {
		if matchesScope(b.scope, tool, session) {
			result = append(result, b)
		}
	}
	return result
}

// matchesScope returns true if the scopeKey matches the given tool and session.
func matchesScope(scope scopeKey, tool, session string) bool {
	if scope.tool != "" && scope.tool != tool {
		return false
	}
	if scope.session != "" && scope.session != session {
		return false
	}
	return true
}

// denyResponse creates a DENY CheckResponse with the given reason and enforcing layer.
func denyResponse(reason string, layer aegis.EnforcingLayer, startNs int64) aegis.CheckResponse {
	return aegis.CheckResponse{
		Decision: aegis.Decision{
			Action: aegis.ActionDeny,
			Reason: reason,
		},
		LatencyNs:      time.Now().UnixNano() - startNs,
		EnforcingLayer: layer,
	}
}

// denyResponseWithVerdict creates a DENY CheckResponse including verdict metadata.
func denyResponseWithVerdict(
	reason string,
	layer aegis.EnforcingLayer,
	startNs int64,
	verdict classify.VerdictEntry,
) aegis.CheckResponse {
	var severity string
	switch verdict.RiskLevel {
	case classify.RiskCritical:
		severity = "critical"
	case classify.RiskHigh:
		severity = "high"
	case classify.RiskMedium:
		severity = "medium"
	case classify.RiskLow:
		severity = "low"
	case classify.RiskNone:
		severity = ""
	}
	return aegis.CheckResponse{
		Decision: aegis.Decision{
			Action: aegis.ActionDeny,
			Reason: reason,
		},
		LatencyNs:      time.Now().UnixNano() - startNs,
		EnforcingLayer: layer,
		ThreatSeverity: severity,
	}
}

// extractCommandText extracts the command text from Bash tool arguments.
func extractCommandText(args json.RawMessage) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return "", false
	}
	cmd, ok := m["command"]
	if !ok {
		return "", false
	}
	s, ok := cmd.(string)
	return s, ok
}

// noopSecretScanner is the MVP-1 stub that always returns no findings.
type noopSecretScanner struct{}

func (n *noopSecretScanner) ScanBoundary(_ context.Context, _ string, _ BoundaryType) ([]Finding, aegis.SecurityLabel) {
	return nil, aegis.SecurityLabel{}
}

func (n *noopSecretScanner) ShouldScan(_ []string, _ BoundaryType) bool {
	return false
}

// noopDelegationValidator is the MVP-1 stub that always succeeds.
type noopDelegationValidator struct{}

func (n *noopDelegationValidator) Validate(_ []aegis.DelegationRef, _ time.Time) error {
	return nil
}

// compile-time interface assertion
var _ aegis.Engine = (*PolicyEngine)(nil)
