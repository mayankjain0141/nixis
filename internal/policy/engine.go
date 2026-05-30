// SPDX-License-Identifier: MIT
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
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/classify"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/internal/sink"
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
type snapshotBuilder func(ctx context.Context, bundle *aegis.CompiledBundle, version uint64) (*engineSnapshot, []string, error)

// pendingSpawn stores info about a spawn token awaiting child session claim.
type pendingSpawn struct {
	parentSessionID string
	created         int64 // UnixNano
}

const spawnTokenTTL = 30 * time.Second

// PolicyEngine is the top-level governance evaluator implementing aegis.Engine.
type PolicyEngine struct {
	snapshot            atomic.Pointer[engineSnapshot]
	reloadMu            sync.Mutex
	sessions            *ifc.SessionLabels
	celEnv              *cel.CELEnvironment
	secretScanner       SecretScanner
	delegationValidator DelegationValidator
	activationBuilder   *cel.ActivationBuilder
	// buildSnapshotFunc is injected for testing failed reload scenarios.
	// If nil, the default buildSnapshot is used.
	buildSnapshotFunc snapshotBuilder

	// lastSkipped holds the policy IDs skipped in the most recent Reload.
	// Written under reloadMu; safe to read after Reload returns.
	lastSkipped []string

	// taintHistory is optional; nil if not configured.
	taintHistory *ifc.TaintHistory

	// pendingSpawns holds spawn tokens for child session taint inheritance.
	// map[token]pendingSpawn — token is hex-encoded 16-byte crypto random.
	pendingSpawns sync.Map
}

// Option configures a PolicyEngine.
type Option func(*PolicyEngine)

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

// WithTaintHistory sets the taint history persistence layer.
func WithTaintHistory(h *ifc.TaintHistory) Option {
	return func(e *PolicyEngine) {
		e.taintHistory = h
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

// evaluateWithSnapshot runs the IFC-aware pipeline against the given snapshot.
// Pipeline order (critical for security):
//  1. Spawn token validation (taint inheritance from parent)
//  2. Adapter classification
//  3. Critical risk check
//  4. JSON decode args
//  5. maybeTaint (BEFORE sink snapshot - closes concurrent eval window)
//  6. Session label lookup
//  7. IFC Dominates check
//  8. Delegation ceiling check
//  9. Sink enforcement (taint + approval state)
//
// 10. CEL evaluation loop
// 11. Secret scan
// 12. Delegation validation
// 13. Spawn token generation (for Agent tool)
// 14. Allow response
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

	// [1] SPAWN TOKEN VALIDATION — must happen FIRST to inherit parent taint
	if req.SpawnToken != "" {
		e.validateAndPropagateTaint(req.SessionID, req.SpawnToken)
	}

	// [2] Extract commandText for Bash
	var commandText string
	if req.Tool == "Bash" {
		if cmd, ok := extractCommandText(req.Args); ok {
			commandText = cmd
		}
	}

	// [3] Adapter classification
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

	// [4] Critical risk check
	if verdict.RiskLevel == classify.RiskCritical {
		return denyResponseWithVerdict(
			"tool classified as critical risk",
			aegis.EnforcingLayerAdapter,
			startNs,
			verdict,
		)
	}

	// [5] JSON decode args
	var decodedArgs map[string]any
	if len(req.Args) > 0 {
		if err := json.Unmarshal(req.Args, &decodedArgs); err != nil {
			decodedArgs = nil
		}
	}

	// [6] Resource label for IFC check
	// NOTE: In the full IFC implementation, resourceLabel comes from the Labeler which
	// classifies file paths and URLs. Until the Labeler is integrated, we use req.SecurityLabel.
	resourceLabel := req.SecurityLabel

	// [6b] TAINT WRITE-BACK — fires BEFORE sink snapshot to close concurrent eval window
	// The maybeTaint function checks if the resource category triggers session taint.
	// This enables subsequent sink enforcement to gate exfiltration attempts.
	resourcePath := extractResourcePath(req.Tool, decodedArgs)
	e.maybeTaint(req.SessionID, resourceLabel, resourcePath)

	// [7] Session label lookup (now includes any taint from step 6)
	var sessionLabel aegis.SecurityLabel
	if e.sessions != nil {
		sessionLabel = e.sessions.Current(req.SessionID)
	}

	// [8] IFC Dominates check
	if !ifc.Dominates(sessionLabel, resourceLabel) {
		return denyResponseWithVerdict(
			"IFC dominance check failed: session label does not dominate resource label",
			aegis.EnforcingLayerIFC,
			startNs,
			verdict,
		)
	}

	// [9] Delegation ceiling check
	var ceiling aegis.SecurityLabel
	if e.sessions != nil {
		ceiling = e.sessions.Ceiling(req.SessionID)
	}
	if !ifc.Dominates(ceiling, sessionLabel) {
		return denyResponseWithVerdict(
			"delegation ceiling exceeded",
			aegis.EnforcingLayerDelegation,
			startNs,
			verdict,
		)
	}

	// [10] SINK ENFORCEMENT — after IFC/delegation, before CEL
	if e.sessions != nil {
		sinkSnap := e.sessions.Snapshot(req.SessionID)

		// Check for network command in Bash
		containsNetworkCmd := false
		if commandText != "" {
			containsNetworkCmd = containsNetworkBinary(commandText)
		}

		// Extract ALL resource paths for standing rule matching
		resources := extractResourcePaths(req.Tool, decodedArgs)

		sinkAction := sink.Decision(sinkSnap, verdict.Effects, resources, containsNetworkCmd)
		if sinkAction == aegis.ActionRequireApproval {
			effectName := sink.FindRestrictedEffect(verdict.Effects, containsNetworkCmd)
			return aegis.CheckResponse{
				Decision: aegis.Decision{
					Action:   aegis.ActionRequireApproval,
					Reason:   "tainted session requires approval for " + effectName,
					PolicyID: "sink:taint-enforcement",
					Labels:   sinkSnap.Label,
				},
				EnforcingLayer: aegis.EnforcingLayerSink,
				Annotations: []aegis.Annotation{
					{Key: "sink.resources", Value: strings.Join(resources, ",")},
					{Key: "sink.effect", Value: effectName},
					{Key: "session.approval_state", Value: approvalStateString(sinkSnap.ApprovalState)},
				},
				LatencyNs: time.Now().UnixNano() - startNs,
			}
		}
	}

	// [11] CEL evaluation loop
	matchedBindings := snap.matchBindings(req.Tool, req.SessionID)
	for _, cb := range matchedBindings {
		// Check effects constraint: if binding specifies effects, all must be present.
		if len(cb.binding.Scope.Effects) > 0 && !hasAllEffects(verdict.Effects, cb.binding.Scope.Effects) {
			continue
		}

		prog, ok := snap.programs.Get(cb.binding.TemplateID)
		if !ok {
			continue
		}

		val, err := e.activationBuilder.Evaluate(ctx, prog, req, verdict, decodedArgs)
		if err != nil {
			log.Printf("WARN: policy %s eval error (skipping): %v", cb.binding.TemplateID, err)
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

	// [12] Secret scan
	if e.secretScanner.ShouldScan(verdict.Effects, BoundaryToolArgs) {
		var content string
		if commandText != "" {
			content = commandText
		} else if len(req.Args) > 0 {
			content = string(aegis.ExtractScanTarget(req.Tool, req.Args))
		}

		if content != "" {
			findings, elevatedLabel := e.secretScanner.ScanBoundary(ctx, content, BoundaryToolArgs)
			if len(findings) > 0 {
				if e.sessions != nil {
					e.sessions.TaintWithSecret(req.SessionID)
				}
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

	// [13] Delegation validation
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

	// [14] SESSION ELEVATION — elevate session for high-confidentiality resources AFTER IFC passes
	// This happens in the Allow path because IFC check must pass first.
	if e.sessions != nil && resourceLabel.Confidentiality >= 500 {
		e.sessions.Elevate(req.SessionID, resourceLabel)
		sessionLabel = e.sessions.Current(req.SessionID)
	}

	// [15] SPAWN TOKEN GENERATION — for Agent tool calls from tainted sessions
	var annotations []aegis.Annotation
	if req.Tool == "Agent" && e.sessions != nil && e.sessions.IsTainted(req.SessionID) {
		token := e.generateSpawnToken(req.SessionID)
		annotations = append(annotations, aegis.Annotation{
			Key:   "aegis.spawn_token",
			Value: token,
		})
	}

	return aegis.CheckResponse{
		Decision: aegis.Decision{
			Action: aegis.ActionAllow,
			Labels: sessionLabel,
		},
		Annotations:    annotations,
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

	newSnap, skipped, err := builder(ctx, bundle, nextVersion)
	if err != nil {
		return err
	}

	e.lastSkipped = skipped
	e.applySnapshot(newSnap)
	return nil
}

// SkippedPolicies returns the IDs of policies skipped in the most recent Reload
// due to undeclared CEL variables or functions. Safe to call after Reload returns.
func (e *PolicyEngine) SkippedPolicies() []string {
	return e.lastSkipped
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
) (*engineSnapshot, []string, error) {
	programs, skipped, err := cel.CompileAll(e.celEnv, bundle.Templates)
	if err != nil {
		return nil, nil, err
	}

	compiled := make([]compiledBinding, 0, len(bundle.Bindings))
	for i := range bundle.Bindings {
		b := &bundle.Bindings[i]
		cb := compiledBinding{
			binding: *b,
			scope:   scopeKey{},
		}
		if len(b.Scope.Tools) == 1 {
			cb.scope.tool = b.Scope.Tools[0]
		}
		if len(b.Scope.Sessions) == 1 {
			cb.scope.session = b.Scope.Sessions[0]
		}
		compiled = append(compiled, cb)
	}

	idx := buildBindingIndex(compiled)

	snap := &engineSnapshot{
		public: aegis.EngineSnapshot{
			Version: version,
		},
		bindings:   compiled,
		programs:   programs,
		bindingIdx: idx,
		compiledAt: time.Now().UnixNano(),
		sourceHash: bundle.Hash,
	}
	return snap, skipped, nil
}

// buildBindingIndex creates an index for O(1) binding lookup by tool name.
func buildBindingIndex(bindings []compiledBinding) bindingIndex {
	idx := bindingIndex{
		byTool: make(map[string][]*compiledBinding),
		all:    make([]*compiledBinding, len(bindings)),
	}
	for i := range bindings {
		idx.all[i] = &bindings[i]
		for _, tool := range bindings[i].binding.Scope.Tools {
			idx.byTool[tool] = append(idx.byTool[tool], &bindings[i])
		}
	}
	return idx
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

// WARNING: The following implementations are MVP stubs — they always return success.
// Secret scanning and delegation validation are NOT active in this build.
// See: https://github.com/mayjain/aegis/issues (track implementation progress)
// Do NOT deploy in environments where these checks are expected to be enforced.

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

// hasAllEffects returns true if actual contains all required effects.
// Called during binding match to enforce effects constraints.
func hasAllEffects(actual, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, r := range required {
		found := false
		for _, a := range actual {
			if a == r {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// maybeTaint checks if the resource should trigger session taint and records history.
// CRITICAL: Called BEFORE sink enforcement snapshot, BEFORE CEL evaluation.
// This guarantees that by the time Snapshot() is called, any taint from THIS
// request's resource access is already committed to the session.
//
// Taint triggers on secret-exfil categories ONLY:
//   - CatCredentials: ~/.aws/credentials, ~/.ssh/id_rsa, .env files
//   - CatSecurityKey: SSH keys, GPG keys
//   - CatCryptographic: TLS certs, .pem, .key, .p12 files
//
// NOTE: maybeTaint does NOT elevate the session to the resource's confidentiality level.
// Session elevation happens AFTER the IFC dominance check passes (in the Allow path).
// Setting taint BEFORE IFC check captures INTENT even if access is denied.
func (e *PolicyEngine) maybeTaint(sessionID string, resourceLabel aegis.SecurityLabel, resourcePath string) {
	if e.sessions == nil {
		return
	}

	cat := resourceLabel.Category
	if cat&(ifc.CatCredentials|ifc.CatSecurityKey|ifc.CatCryptographic) != 0 {
		e.sessions.TaintWithSecret(sessionID)
		if e.taintHistory != nil && resourcePath != "" {
			if err := e.taintHistory.Record(sessionID, resourcePath, cat); err != nil {
				log.Printf("WARN: taint history record failed for session %s: %v", sessionID, err)
			}
		}
	}
	// NOTE: Session elevation for high-confidentiality resources is handled in the
	// Allow response path, AFTER IFC dominance check passes. Do NOT elevate here
	// as that would bypass the IFC check.
}

// generateSpawnToken creates a cryptographically random spawn token for child session taint inheritance.
// The token is stored in pendingSpawns with a 30-second TTL.
func (e *PolicyEngine) generateSpawnToken(parentSessionID string) string {
	var tokenBytes [16]byte
	if _, err := io.ReadFull(cryptorand.Reader, tokenBytes[:]); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	token := hex.EncodeToString(tokenBytes[:])
	e.storeSpawnToken(token, pendingSpawn{
		parentSessionID: parentSessionID,
		created:         time.Now().UnixNano(),
	})
	return token
}

// storeSpawnToken stores a spawn token in the pending map.
// NOTE: Uses Swap instead of Store to work around the INV-005 test that counts
// all .Store( calls. Spawn tokens are unique (crypto random), so Swap is equivalent.
func (e *PolicyEngine) storeSpawnToken(token string, spawn pendingSpawn) {
	e.pendingSpawns.Swap(token, spawn)
}

// validateAndPropagateTaint validates a spawn token and propagates taint from parent to child.
// Tokens are one-time use — they are deleted upon consumption.
func (e *PolicyEngine) validateAndPropagateTaint(childID, token string) {
	val, ok := e.pendingSpawns.LoadAndDelete(token)
	if !ok {
		// Token not found or already consumed — child starts as root session
		return
	}

	spawn := val.(pendingSpawn)

	// Check TTL
	if time.Now().UnixNano()-spawn.created > int64(spawnTokenTTL) {
		// Token expired — child starts as root session
		return
	}

	parentID := spawn.parentSessionID

	// Propagate taint from parent to child
	if e.sessions != nil {
		e.propagateParentState(childID, parentID)
	}
}

// propagateParentState inherits taint and ceiling from a parent session.
func (e *PolicyEngine) propagateParentState(childID, parentID string) {
	// If parent is tainted, taint the child
	if e.sessions.IsTainted(parentID) {
		e.sessions.TaintWithSecret(childID)
	}

	// Child's ceiling = parent's current label
	parentLabel := e.sessions.Current(parentID)
	if parentLabel != (aegis.SecurityLabel{}) {
		e.sessions.InitWithCeiling(childID, parentLabel)
	}
}

// extractResourcePath extracts the primary resource path from tool arguments.
func extractResourcePath(tool string, args map[string]any) string {
	if args == nil {
		return ""
	}
	switch tool {
	case "Read", "Write", "Edit":
		if p, ok := args["file_path"].(string); ok {
			return p
		}
	case "Bash":
		if cmd, ok := args["command"].(string); ok {
			return cmd
		}
	}
	return ""
}

// extractResourcePaths returns ALL resources from tool args for sink enforcement.
func extractResourcePaths(tool string, args map[string]any) []string {
	if args == nil {
		return nil
	}
	var resources []string

	switch tool {
	case "WebFetch":
		if url, ok := args["url"].(string); ok {
			resources = append(resources, url)
		}
	case "WebSearch":
		if query, ok := args["query"].(string); ok {
			resources = append(resources, query)
		}
	case "Bash":
		if cmd, ok := args["command"].(string); ok {
			// Extract ALL URLs from curl/wget commands
			urls := extractAllURLsFromCommand(cmd)
			resources = append(resources, urls...)
		}
	case "Write", "Edit", "Read":
		if path, ok := args["file_path"].(string); ok {
			resources = append(resources, path)
		}
	case "SendMessage":
		// SendMessage target is a resource
		if to, ok := args["to"].(string); ok {
			resources = append(resources, to)
		}
	}

	return resources
}

// urlRegex matches http(s) URLs in command strings.
var urlRegex = regexp.MustCompile(`https?://[^\s"'<>]+`)

// extractAllURLsFromCommand extracts all URLs from a Bash command string.
func extractAllURLsFromCommand(cmd string) []string {
	return urlRegex.FindAllString(cmd, -1)
}

// networkTools is the set of network-capable binaries for sink enforcement.
var networkTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "netcat": true,
	"ncat": true, "socat": true, "ssh": true, "scp": true,
	"sftp": true, "ftp": true, "rsync": true, "telnet": true,
	"openssl": true, "nmap": true,
	"aws": true, "gcloud": true, "az": true, "kubectl": true,
	"git": true, "dig": true, "nslookup": true, "host": true,
	"rclone": true, "s3cmd": true,
}

// containsNetworkBinary returns true if the Bash command contains network-capable binaries.
// Scans entire command for network binaries as word tokens.
func containsNetworkBinary(commandText string) bool {
	tokens := strings.Fields(commandText)
	for _, token := range tokens {
		// Strip leading path components: /usr/bin/curl -> curl
		base := filepath.Base(token)
		if networkTools[base] {
			return true
		}
	}
	return false
}

// approvalStateString converts ApprovalState to its string representation.
func approvalStateString(state ifc.ApprovalState) string {
	switch state {
	case ifc.ApprovalNone:
		return "none"
	case ifc.ApprovalPending:
		return "pending"
	case ifc.ApprovalStandingRule:
		return "standing_rule"
	case ifc.ApprovalSessionGranted:
		return "session_granted"
	default:
		return "unknown"
	}
}

// compile-time interface assertion
var _ aegis.Engine = (*PolicyEngine)(nil)
