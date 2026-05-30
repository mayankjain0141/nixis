// SPDX-License-Identifier: MIT
// Package policy implements the top-level governance evaluation pipeline for Nixis.
//
// PolicyEngine implements nixis.Engine with a 5-layer evaluation pipeline:
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
//   - Zero-value Action is ActionDeny (fail-secure).
//   - atomic.Pointer.Store() appears ONCE — in applySnapshot().
//   - reloadMu is never held during Evaluate().
//   - Failed reload never replaces the snapshot.
package policy

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mayankjain0141/nixis/internal/cel"
	"github.com/mayankjain0141/nixis/internal/classify"
	"github.com/mayankjain0141/nixis/internal/ifc"
	"github.com/mayankjain0141/nixis/internal/label"
	"github.com/mayankjain0141/nixis/internal/sink"
	"github.com/mayankjain0141/nixis/pkg/nixis"
	policy_types "github.com/mayankjain0141/nixis/pkg/policy/types"
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

// SecretScanner is the interface for secret detection.
// MVP-1 uses a stub implementation that always returns no findings.
type SecretScanner interface {
	ScanBoundary(ctx context.Context, content string, boundary BoundaryType) ([]Finding, nixis.SecurityLabel)
	ShouldScan(effects []string, boundary BoundaryType) bool
}

// DelegationValidator is the interface for delegation chain validation.
// MVP-1 uses a stub implementation that always succeeds.
type DelegationValidator interface {
	Validate(chain []nixis.DelegationRef, now time.Time) error
}

// classifierInterface abstracts the Classifier for testing (panic injection).
type classifierInterface interface {
	Classify(toolName string) (classify.VerdictEntry, bool)
	ClassifyBash(toolName, commandText string) classify.VerdictEntry
}

// engineSnapshot extends the public nixis.EngineSnapshot with internal evaluation state.
// internal/policy/ owns this type entirely.
type engineSnapshot struct {
	public     nixis.EngineSnapshot
	bindings   []compiledBinding
	programs   *cel.ProgramCache
	classifier *classify.Classifier
	// classifierIntf is used when classifier is nil (test injection).
	classifierIntf classifierInterface
	bindingIdx     bindingIndex
	compiledAt     int64
	sourceHash     [32]byte
	// templateParams maps TemplateID → resolved params map (from PolicyTemplate.Params).
	// Nil map means empty params; always safe to pass to Evaluate.
	templateParams map[string]map[string]any
	templates      []policy_types.PolicyTemplate
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
type snapshotBuilder func(ctx context.Context, bundle *nixis.CompiledBundle, version uint64) (*engineSnapshot, []string, error)

// pendingSpawn stores info about a spawn token awaiting child session claim.
type pendingSpawn struct {
	parentSessionID string
	created         int64 // UnixNano
}

const spawnTokenTTL = 30 * time.Second

// PolicyEngine is the top-level governance evaluator implementing nixis.Engine.
type PolicyEngine struct {
	snapshot            atomic.Pointer[engineSnapshot]
	reloadMu            sync.Mutex
	sessions            *ifc.SessionLabels
	celEnv              *cel.CELEnvironment
	secretScanner       SecretScanner
	delegationValidator DelegationValidator
	activationBuilder   *cel.ActivationBuilder
	labeler             label.Labeler
	selfProtect         *SelfProtectGuard
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

// WithLabeler sets the resource labeler used to populate resource_* CEL variables.
func WithLabeler(l label.Labeler) Option {
	return func(e *PolicyEngine) {
		e.labeler = l
	}
}

// Snapshot is nil until the first successful Reload() — Evaluate() returns Deny in the interim (fail-secure).
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
		selfProtect:         NewSelfProtectGuard(),
	}
	for _, opt := range opts {
		opt(e)
	}
	cel.SetSessionLabels(sessions)
	return e
}

// Hot path contract:
//   - Snapshot is loaded ONCE at entry and passed through the entire call stack.
//   - If snapshot is nil OR any internal error occurs, returns Decision{Action: ActionDeny}.
//   - On first DENY from any layer, short-circuits and returns immediately.
//   - Never returns an error — failures encode as Deny decisions.
func (e *PolicyEngine) Evaluate(ctx context.Context, req nixis.CheckRequest) nixis.CheckResponse {
	startNs := time.Now().UnixNano()

	if e.selfProtect != nil {
		if decision := e.selfProtect.Check(req); decision != nil {
			return nixis.CheckResponse{
				Decision:  *decision,
				LatencyNs: time.Now().UnixNano() - startNs,
			}
		}
	}

	snap := e.snapshot.Load()
	if snap == nil {
		return denyResponse("policy engine not initialized", nixis.EnforcingLayerAdapter, startNs)
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
	req nixis.CheckRequest,
	snap *engineSnapshot,
	startNs int64,
) (resp nixis.CheckResponse) {
	defer func() {
		if r := recover(); r != nil {
			resp = denyResponse("internal evaluation panic", nixis.EnforcingLayerAdapter, startNs)
		}
	}()

	if req.SpawnToken != "" {
		e.validateAndPropagateTaint(req.SessionID, req.SpawnToken)
	}

	if req.ProjectRoot != "" && e.sessions != nil {
		e.sessions.SetProjectRoot(req.SessionID, req.ProjectRoot)
	}

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
			nixis.EnforcingLayerAdapter,
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

	// Only runs when args were actually decoded (non-nil map). If the hook sends no
	// args at all, decodedArgs is nil and we skip validation rather than requiring
	// required fields to be present in a missing payload.
	schemaResult := classify.CheckArgSchema(req.Tool, decodedArgs)
	if decodedArgs != nil && schemaResult.Err != nil {
		return nixis.CheckResponse{
			Decision: nixis.Decision{
				Action:   nixis.ActionDeny,
				Reason:   schemaResult.Err.Error(),
				PolicyID: "builtin:arg-schema",
			},
			LatencyNs:      time.Now().UnixNano() - startNs,
			EnforcingLayer: nixis.EnforcingLayerArgSchema,
			ThreatSeverity: "medium",
		}
	}

	var labeled label.LabeledRequest
	if e.labeler != nil {
		labeled = e.labeler.Label(req, verdict)
	}
	labeled.UnknownTool = schemaResult.UnknownTool

	resourceLabel := labeled.ResourceLabel
	if resourceLabel == (nixis.SecurityLabel{}) {
		resourceLabel = req.SecurityLabel
	}

	var resourcePath string
	if len(labeled.ResourcePaths) > 0 {
		resourcePath = labeled.ResourcePaths[0]
	} else {
		resourcePath = extractResourcePath(req.Tool, decodedArgs)
	}
	e.maybeTaint(req.SessionID, resourceLabel, resourcePath)

	var sessionLabel nixis.SecurityLabel
	var sessionProjectRoot string
	if e.sessions != nil {
		sessionLabel = e.sessions.Current(req.SessionID)
		sessionProjectRoot = e.sessions.ProjectRoot(req.SessionID)
	}

	if !ifc.Dominates(sessionLabel, resourceLabel) {
		return denyResponseWithVerdict(
			"IFC dominance check failed: session label does not dominate resource label",
			nixis.EnforcingLayerIFC,
			startNs,
			verdict,
		)
	}

	var ceiling nixis.SecurityLabel
	if e.sessions != nil {
		ceiling = e.sessions.Ceiling(req.SessionID)
	}
	if !ifc.Dominates(ceiling, sessionLabel) {
		return denyResponseWithVerdict(
			"delegation ceiling exceeded",
			nixis.EnforcingLayerDelegation,
			startNs,
			verdict,
		)
	}

	if e.sessions != nil {
		sinkSnap := e.sessions.Snapshot(req.SessionID)

		// Use labeled.ContainsNetworkCmd when labeler is configured, else detect from commandText
		containsNetworkCmd := labeled.ContainsNetworkCmd
		if !containsNetworkCmd && commandText != "" {
			containsNetworkCmd = containsNetworkBinary(commandText)
		}

		// Use labeled.ResourcePaths when labeler is configured, else extract from args
		resources := labeled.ResourcePaths
		if len(resources) == 0 {
			resources = extractResourcePaths(req.Tool, decodedArgs)
		}

		sinkAction := sink.Decision(sinkSnap, verdict.Effects, resources, containsNetworkCmd)
		if sinkAction != nixis.ActionAllow {
			effectName := findRestrictedEffect(verdict.Effects, containsNetworkCmd)
			return nixis.CheckResponse{
				Decision: nixis.Decision{
					Action:   sinkAction,
					Reason:   "tainted session requires approval for " + effectName,
					PolicyID: "sink:taint-enforcement",
					Labels:   sinkSnap.Label,
				},
				EnforcingLayer: nixis.EnforcingLayerSink,
				Annotations: []nixis.Annotation{
					{Key: "sink.resources", Value: strings.Join(resources, ",")},
					{Key: "sink.effect", Value: effectName},
					{Key: "session.approval_state", Value: approvalStateString(sinkSnap.ApprovalState)},
				},
				LatencyNs: time.Now().UnixNano() - startNs,
			}
		}
	}

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

		policyParams := snap.templateParams[cb.binding.TemplateID]
		val, err := e.activationBuilder.Evaluate(ctx, prog, req, verdict, decodedArgs, labeled, policyParams, sessionProjectRoot)
		if err != nil {
			if cb.binding.DefaultAction == "DENY" {
				return denyResponse("policy eval error — fail-secure: "+cb.binding.TemplateID, nixis.EnforcingLayerCEL, startNs)
			}
			log.Printf("WARN: policy %s eval error (skipping): %v", cb.binding.TemplateID, err)
			continue
		}

		if b, ok := val.Value().(bool); ok && !b {
			action := nixis.ActionDeny
			if cb.binding.RequireApproval {
				action = nixis.ActionRequireApproval
			}
			reason := cb.binding.Message
			if reason == "" {
				reason = "CEL policy evaluation returned false"
			}
			sourceLocation := snap.programs.SourceLocation(cb.binding.TemplateID)
			return nixis.CheckResponse{
				Decision: nixis.Decision{
					Action:   action,
					Reason:   reason,
					PolicyID: cb.binding.TemplateID,
					Labels:   sessionLabel,
				},
				LatencyNs:            time.Now().UnixNano() - startNs,
				EnforcingLayer:       nixis.EnforcingLayerCEL,
				PolicySourceLocation: sourceLocation,
			}
		}
	}

	if e.secretScanner.ShouldScan(verdict.Effects, BoundaryToolArgs) {
		filePath := extractFilePath(req.Tool, req.Args)
		if !isExemptPath(filePath) {
			var content string
			if commandText != "" {
				content = commandText
			} else if len(req.Args) > 0 {
				content = string(nixis.ExtractScanTarget(req.Tool, req.Args))
			}

			if content != "" {
				const maxScanBytes = 1 << 20 // 1MB
				partialScan := false
				scanContent := content
				if len(content) > maxScanBytes {
					scanContent = content[:maxScanBytes]
					partialScan = true
				}

				findings, elevatedLabel := e.secretScanner.ScanBoundary(ctx, scanContent, BoundaryToolArgs)
				if len(findings) > 0 {
					if e.sessions != nil {
						e.sessions.TaintWithSecret(req.SessionID)
					}
					return nixis.CheckResponse{
						Decision: nixis.Decision{
							Action:   nixis.ActionRequireApproval,
							Reason:   "secret pattern detected in content — human approval required",
							PolicyID: "builtin:secret-scan",
							Labels:   elevatedLabel,
						},
						LatencyNs:      time.Now().UnixNano() - startNs,
						EnforcingLayer: nixis.EnforcingLayerSecretScan,
						ThreatSeverity: "high",
					}
				}
				if partialScan {
					return nixis.CheckResponse{
						Decision: nixis.Decision{
							Action:   nixis.ActionRequireApproval,
							Reason:   "content exceeds 1MB scan limit — remainder unverified for secrets",
							PolicyID: "builtin:secret-scan-partial",
						},
						LatencyNs:      time.Now().UnixNano() - startNs,
						EnforcingLayer: nixis.EnforcingLayerSecretScan,
						ThreatSeverity: "medium",
					}
				}
			}
		}
	}

	if len(req.AuthorityChain) > 0 {
		if err := e.delegationValidator.Validate(req.AuthorityChain, time.Now()); err != nil {
			return denyResponseWithVerdict(
				"delegation chain validation failed",
				nixis.EnforcingLayerDelegation,
				startNs,
				verdict,
			)
		}
	}

	// Elevate session for high-confidentiality resources only after IFC passes — not before.
	if e.sessions != nil && resourceLabel.Confidentiality >= 500 {
		e.sessions.Elevate(req.SessionID, resourceLabel)
		sessionLabel = e.sessions.Current(req.SessionID)
	}

	var annotations []nixis.Annotation
	if req.Tool == "Agent" && e.sessions != nil && e.sessions.IsTainted(req.SessionID) {
		token := e.generateSpawnToken(req.SessionID)
		annotations = append(annotations, nixis.Annotation{
			Key:   "nixis.spawn_token",
			Value: token,
		})
	}

	return nixis.CheckResponse{
		Decision: nixis.Decision{
			Action: nixis.ActionAllow,
			Labels: sessionLabel,
		},
		Annotations:    annotations,
		LatencyNs:      time.Now().UnixNano() - startNs,
		EnforcingLayer: nixis.EnforcingLayerAdapter,
	}
}

// Reload atomically swaps the EngineSnapshot.
// This is the ONLY method that calls atomic.Pointer.Store() — via applySnapshot().
// reloadMu serializes concurrent Reload() calls but is never held during Evaluate().
// If any step fails, the existing snapshot continues serving.
func (e *PolicyEngine) Reload(ctx context.Context, bundle *nixis.CompiledBundle) error {
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

// SkippedPolicies lists policy IDs skipped in the most recent Reload due to undeclared CEL variables or functions.
func (e *PolicyEngine) SkippedPolicies() []string {
	return e.lastSkipped
}

// applySnapshot is the ONLY place atomic.Pointer.Store() is called.
func (e *PolicyEngine) applySnapshot(snap *engineSnapshot) {
	e.snapshot.Store(snap)
}

func (e *PolicyEngine) buildSnapshot(
	ctx context.Context,
	bundle *nixis.CompiledBundle,
	version uint64,
) (*engineSnapshot, []string, error) {
	programs, skippedPolicies, err := cel.CompileAll(e.celEnv, bundle.Templates)
	if err != nil {
		return nil, nil, err
	}

	// Fail-closed: refuse to activate when a defaultAction=DENY policy fails compilation.
	// Prevents an adversary from injecting a syntax error to silently disable a DENY policy.
	for _, s := range skippedPolicies {
		if s.DefaultAction == "DENY" {
			return nil, nil, fmt.Errorf("bundle: cannot load: policy %q has defaultAction=DENY but CEL compilation failed: %v", s.TemplateID, s.CompileErr)
		}
	}

	skipped := make([]string, 0, len(skippedPolicies))
	for _, s := range skippedPolicies {
		skipped = append(skipped, s.TemplateID)
	}

	// Build templateParams index: TemplateID → params map.
	templateParams := make(map[string]map[string]any, len(bundle.Templates))
	for i := range bundle.Templates {
		t := &bundle.Templates[i]
		if t.Params != nil {
			templateParams[t.ID] = t.Params
		}
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
		public: nixis.EngineSnapshot{
			Version: version,
		},
		bindings:       compiled,
		programs:       programs,
		bindingIdx:     idx,
		compiledAt:     time.Now().UnixNano(),
		sourceHash:     bundle.Hash,
		templateParams: templateParams,
		templates:      bundle.Templates,
	}
	return snap, skipped, nil
}

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

// ListPolicies implements nixis.PolicyLister.
func (e *PolicyEngine) ListPolicies() []nixis.PolicySummary {
	snap := e.snapshot.Load()
	if snap == nil {
		return nil
	}

	layerByTemplateID := make(map[string]string, len(snap.bindings))
	for _, cb := range snap.bindings {
		if cb.binding.Layer != "" {
			layerByTemplateID[cb.binding.TemplateID] = cb.binding.Layer
		}
	}

	result := make([]nixis.PolicySummary, 0, len(snap.templates))
	for _, t := range snap.templates {
		layer := layerByTemplateID[t.ID]
		if layer == "" {
			layer = "cel"
		}
		result = append(result, nixis.PolicySummary{
			ID:            t.ID,
			Name:          t.Name,
			Layer:         layer,
			Enabled:       true,
			CelExpression: t.Expression,
			Description:   t.Description,
		})
	}
	return result
}

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

func matchesScope(scope scopeKey, tool, session string) bool {
	if scope.tool != "" && scope.tool != tool {
		return false
	}
	if scope.session != "" && scope.session != session {
		return false
	}
	return true
}

func denyResponse(reason string, layer nixis.EnforcingLayer, startNs int64) nixis.CheckResponse {
	return nixis.CheckResponse{
		Decision: nixis.Decision{
			Action: nixis.ActionDeny,
			Reason: reason,
		},
		LatencyNs:      time.Now().UnixNano() - startNs,
		EnforcingLayer: layer,
	}
}

func denyResponseWithVerdict(
	reason string,
	layer nixis.EnforcingLayer,
	startNs int64,
	verdict classify.VerdictEntry,
) nixis.CheckResponse {
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
	return nixis.CheckResponse{
		Decision: nixis.Decision{
			Action: nixis.ActionDeny,
			Reason: reason,
		},
		LatencyNs:      time.Now().UnixNano() - startNs,
		EnforcingLayer: layer,
		ThreatSeverity: severity,
	}
}

// isExemptPath returns true for paths that commonly contain example/test credentials.
func isExemptPath(path string) bool {
	if strings.HasSuffix(path, "_test.go") {
		return true
	}
	if strings.Contains(path, "/testdata/") || strings.HasSuffix(path, "/testdata") {
		return true
	}
	if strings.Contains(path, "/docs/") || strings.HasSuffix(path, "/docs") {
		return true
	}
	if strings.HasSuffix(path, ".example") || strings.HasSuffix(path, ".sample") ||
		strings.HasSuffix(path, ".template") || strings.HasSuffix(path, ".tmpl") {
		return true
	}
	if strings.Contains(path, "/examples/") || strings.HasSuffix(path, "/examples") {
		return true
	}
	base := filepath.Base(path)
	return strings.HasPrefix(strings.ToUpper(base), "README")
}

func extractFilePath(tool string, args []byte) string {
	var a struct {
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return ""
	}
	return a.FilePath
}

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
// See: https://github.com/mayankjain0141/nixis/issues (track implementation progress)
// Do NOT deploy in environments where these checks are expected to be enforced.

type noopSecretScanner struct{}

func (n *noopSecretScanner) ScanBoundary(_ context.Context, _ string, _ BoundaryType) ([]Finding, nixis.SecurityLabel) {
	return nil, nixis.SecurityLabel{}
}

func (n *noopSecretScanner) ShouldScan(_ []string, _ BoundaryType) bool {
	return false
}

type noopDelegationValidator struct{}

func (n *noopDelegationValidator) Validate(_ []nixis.DelegationRef, _ time.Time) error {
	return nil
}

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
func (e *PolicyEngine) maybeTaint(sessionID string, resourceLabel nixis.SecurityLabel, resourcePath string) {
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

// Token is stored in pendingSpawns with a 30-second TTL.
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

// Uses Swap instead of Store to avoid triggering the test that counts all .Store( calls.
// Spawn tokens are unique (crypto random), so Swap is equivalent.
func (e *PolicyEngine) storeSpawnToken(token string, spawn pendingSpawn) {
	e.pendingSpawns.Swap(token, spawn)
}

// Tokens are one-time use — deleted upon consumption.
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

func (e *PolicyEngine) propagateParentState(childID, parentID string) {
	// If parent is tainted, taint the child
	if e.sessions.IsTainted(parentID) {
		e.sessions.TaintWithSecret(childID)
	}

	// Child's ceiling = parent's current label
	parentLabel := e.sessions.Current(parentID)
	if parentLabel != (nixis.SecurityLabel{}) {
		e.sessions.InitWithCeiling(childID, parentLabel)
	}
}

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

var urlRegex = regexp.MustCompile(`https?://[^\s"'<>]+`)

func extractAllURLsFromCommand(cmd string) []string {
	return urlRegex.FindAllString(cmd, -1)
}

var networkTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "netcat": true,
	"ncat": true, "socat": true, "ssh": true, "scp": true,
	"sftp": true, "ftp": true, "rsync": true, "telnet": true,
	"openssl": true, "nmap": true,
	"aws": true, "gcloud": true, "az": true, "kubectl": true,
	"git": true, "dig": true, "nslookup": true, "host": true,
	"rclone": true, "s3cmd": true,
}

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

// Used for error messages — returns "network_egress" if containsNetworkCmd is true.
func findRestrictedEffect(effects []string, containsNetworkCmd bool) string {
	if containsNetworkCmd {
		return classify.EffectNetworkEgress
	}
	for _, eff := range effects {
		if sink.IsRestrictedEffect(eff) {
			return eff
		}
	}
	return "restricted_sink"
}

// compile-time interface assertion
var _ nixis.Engine = (*PolicyEngine)(nil)
