// SPDX-License-Identifier: MIT
// Package classify implements the three-tier tool classification engine.
//
// Hot path contract: Classify() on a VerdictMap hit MUST be zero-alloc.
// Banned in this package: fmt.Sprintf, encoding/json.Marshal (golangci-lint enforced).
package classify

import (
	"regexp"
	"strings"

	"github.com/mayankjain0141/nixis/pkg/adapters"
)

// Classification describes the nature of a tool call. NOT a final governance decision.
type Classification string

type RiskLevel string

const (
	RiskNone     RiskLevel = "none"
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type ResourceType string

const (
	ResFile              ResourceType = "file"
	ResProcess           ResourceType = "process"
	ResNetwork           ResourceType = "network"
	ResAgentCoordination ResourceType = "agent_coordination"
	ResDatabase          ResourceType = "database"
)

// Effect constants for VerdictEntry.Effects.
const (
	EffectReadFiles           = "read_files"
	EffectWriteFiles          = "write_files"
	EffectExecProcess         = "exec_process"
	EffectNetworkEgress       = "network_egress"
	EffectStateChange         = "state_change"
	EffectCredentialUse       = "credential_use"       // triggers ScanBoundary in WS-09
	EffectContentInternal     = "content_internal"     // SendMessage ONLY — NOT content_publish
	EffectProcessCoordination = "process_coordination" // Agent, TeamCreate, TeamDelete
	EffectContentPublish      = "content_publish"
	EffectMessageContent      = "message_content" // SendMessage and similar coordination tools — triggers secret scan on message body
)

// VerdictEntry provides CLASSIFICATION only — NOT a final governance decision.
// Never add an Action field here. Classification != decision.
type VerdictEntry struct {
	Classification        Classification
	Effects               []string // from AdapterDef.Effects
	RiskLevel             RiskLevel
	DefaultClassification Classification // was "DefaultVerdict" — renamed per RISK-009
	AdapterName           string
	ResourceType          ResourceType
	AdapterMatch          bool // true = exact catalog hit; false = heuristic fallback
}

// coordinationTools is the set of tools that MUST have AdapterMatch=true.
// Populated at init time for O(1) lookup in tests.
var coordinationTools = map[string]struct{}{
	"TaskCreate":   {},
	"TaskUpdate":   {},
	"TaskGet":      {},
	"TaskList":     {},
	"SendMessage":  {},
	"TeamCreate":   {},
	"TeamDelete":   {},
	"Agent":        {},
	"Skill":        {},
	"ExitPlanMode": {},
}

// credentialPatterns is the pre-scan regex set for Bash tool arguments.
// Compiled once at init; never allocated on the hot path.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`export\s+\w+\s*=\s*["']?sk-`),
	regexp.MustCompile(`export\s+\w+\s*=\s*["']?ghp_`),
	regexp.MustCompile(`export\s+\w+\s*=\s*["']?AKIA`),
	regexp.MustCompile(`export\s+\w+\s*=\s*["']?xox[baprs]-`),
}

// verdictMapEntry is the internal storage element in VerdictMap.
// Kept small so the hot path stays cache-friendly.
type verdictMapEntry struct {
	key   string
	value VerdictEntry
}

// VerdictMap is an immutable open-addressing hash table built from the adapter catalog.
// Built once in the reload goroutine; never mutated after Build.
type VerdictMap struct {
	buckets []verdictMapEntry
	mask    uint64
	count   int
}

// BuildVerdictMap constructs an immutable VerdictMap from the catalog.
// Called once during startup or reload; not on the hot path.
func BuildVerdictMap(catalog []adapters.AdapterDef) *VerdictMap {
	n := nextPow2(len(catalog) * 10 / 7) // load factor ≤70%
	if n < 16 {
		n = 16
	}
	vm := &VerdictMap{
		buckets: make([]verdictMapEntry, n),
		mask:    uint64(n - 1),
		count:   0,
	}
	for i := range catalog {
		def := &catalog[i]
		entry := adapterDefToVerdict(def)
		vm.insert(def.Tool, entry)
	}
	return vm
}

// adapterDefToVerdict converts an AdapterDef to a VerdictEntry.
func adapterDefToVerdict(def *adapters.AdapterDef) VerdictEntry {
	cls := classificationFromOperation(def.Operation)
	effects := make([]string, len(def.Effects))
	copy(effects, def.Effects)
	return VerdictEntry{
		Classification:        cls,
		Effects:               effects,
		RiskLevel:             RiskLevel(def.RiskLevel),
		DefaultClassification: cls,
		AdapterName:           def.Family + ":" + def.Tool,
		ResourceType:          ResourceType(def.ResourceType),
		AdapterMatch:          true,
	}
}

// classificationFromOperation maps an operation string to a Classification.
func classificationFromOperation(op string) Classification {
	switch op {
	case "read":
		return "readonly"
	case "write", "update":
		return "write"
	case "exec":
		return "exec"
	case "create":
		return "write"
	case "delete":
		return "write"
	case "publish":
		return "write"
	default:
		return "unknown"
	}
}

// fnv1aHash is an inline FNV-1a hash — no stdlib allocation.
func fnv1aHash(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// insert places an entry into the open-addressing table (linear probing).
func (vm *VerdictMap) insert(key string, value VerdictEntry) {
	h := fnv1aHash(key) & vm.mask
	for {
		if vm.buckets[h].key == "" {
			vm.buckets[h] = verdictMapEntry{key: key, value: value}
			vm.count++
			return
		}
		h = (h + 1) & vm.mask
	}
}

// Classify performs an O(1) exact-match lookup. The bool return indicates a catalog hit.
// Zero-alloc on the hit path.
func (vm *VerdictMap) Classify(toolName string) (VerdictEntry, bool) {
	h := fnv1aHash(toolName) & vm.mask
	for {
		b := &vm.buckets[h]
		if b.key == "" {
			return VerdictEntry{}, false
		}
		if b.key == toolName {
			return b.value, true
		}
		h = (h + 1) & vm.mask
	}
}

// nextPow2 returns the smallest power of two >= n.
func nextPow2(n int) int {
	if n <= 1 {
		return 1
	}
	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n |= n >> 32
	return n + 1
}

// Classifier is a three-tier tool classifier.
//
//	Tier 1: VerdictMap exact match → O(1), zero-alloc
//	Tier 2: prefix match for known tool families (e.g. "mcp__context7__")
//	Tier 3: heuristic verb/noun analysis — AdapterMatch=false
//
// Heuristic is DISABLED for claude-code-coordination tools.
type Classifier struct {
	vm *VerdictMap
}

// NewClassifier builds a Classifier from the adapter catalog.
func NewClassifier(catalog []adapters.AdapterDef) *Classifier {
	return &Classifier{vm: BuildVerdictMap(catalog)}
}

// Classify classifies a tool call using the three-tier dispatch.
// Returns the VerdictEntry and whether an exact catalog match was found.
func (c *Classifier) Classify(toolName string) (VerdictEntry, bool) {
	// Tier 1: exact match
	if entry, ok := c.vm.Classify(toolName); ok {
		return entry, true
	}

	// Coordination tools MUST be in the catalog — never fall through.
	if _, isCoord := coordinationTools[toolName]; isCoord {
		// This is a programming error: catalog is missing a required entry.
		// Return a safe deny-by-classification entry.
		return VerdictEntry{
			Classification:        "unknown",
			RiskLevel:             RiskCritical,
			DefaultClassification: "unknown",
			AdapterMatch:          false,
		}, false
	}

	// Tier 2: prefix match for MCP namespaced tools (e.g. "mcp__server__tool")
	if entry, ok := c.classifyByPrefix(toolName); ok {
		return entry, false
	}

	// Tier 3: heuristic
	return c.heuristic(toolName), false
}

// classifyByPrefix handles MCP-style namespaced tool names.
// Returns AdapterMatch=false since this is not an exact catalog entry.
func (c *Classifier) classifyByPrefix(toolName string) (VerdictEntry, bool) {
	// MCP tools use the pattern "mcp__<server>__<tool>"
	if strings.HasPrefix(toolName, "mcp__") {
		return VerdictEntry{
			Classification:        "network",
			Effects:               []string{EffectNetworkEgress},
			RiskLevel:             RiskMedium,
			DefaultClassification: "network",
			AdapterName:           "heuristic:mcp-prefix",
			ResourceType:          ResNetwork,
			AdapterMatch:          false,
		}, true
	}
	return VerdictEntry{}, false
}

// heuristic classifies an unknown tool by verb/noun analysis.
// Returns AdapterMatch=false always.
func (c *Classifier) heuristic(toolName string) VerdictEntry {
	lower := strings.ToLower(toolName)

	// Write indicators
	if hasAnyPrefix(lower, "write", "create", "update", "delete", "remove", "rm", "mv", "cp", "put", "set", "save", "store") {
		return VerdictEntry{
			Classification:        "write",
			Effects:               []string{EffectWriteFiles},
			RiskLevel:             RiskMedium,
			DefaultClassification: "write",
			AdapterName:           "heuristic",
			ResourceType:          ResFile,
			AdapterMatch:          false,
		}
	}

	// Network indicators
	if hasAnyPrefix(lower, "fetch", "download", "upload", "send", "post", "request", "http", "curl", "wget") {
		return VerdictEntry{
			Classification:        "network",
			Effects:               []string{EffectNetworkEgress},
			RiskLevel:             RiskMedium,
			DefaultClassification: "network",
			AdapterName:           "heuristic",
			ResourceType:          ResNetwork,
			AdapterMatch:          false,
		}
	}

	// Exec indicators
	if hasAnyPrefix(lower, "run", "exec", "execute", "spawn", "start", "launch", "invoke") {
		return VerdictEntry{
			Classification:        "exec",
			Effects:               []string{EffectExecProcess},
			RiskLevel:             RiskHigh,
			DefaultClassification: "exec",
			AdapterName:           "heuristic",
			ResourceType:          ResProcess,
			AdapterMatch:          false,
		}
	}

	// Read/query indicators (safe fallback)
	if hasAnyPrefix(lower, "read", "get", "list", "show", "view", "describe", "query", "search", "find", "grep") {
		return VerdictEntry{
			Classification:        "readonly",
			Effects:               []string{EffectReadFiles},
			RiskLevel:             RiskLow,
			DefaultClassification: "readonly",
			AdapterName:           "heuristic",
			ResourceType:          ResFile,
			AdapterMatch:          false,
		}
	}

	// Unknown — conservative default
	return VerdictEntry{
		Classification:        "unknown",
		Effects:               []string{},
		RiskLevel:             RiskHigh,
		DefaultClassification: "unknown",
		AdapterName:           "heuristic",
		ResourceType:          ResFile,
		AdapterMatch:          false,
	}
}

// hasAnyPrefix checks if s starts with any of the given prefixes.
// Inline — no allocation.
func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// ClassifyBash classifies a Bash tool call, running the credential pre-scan
// before heuristic analysis. This is the entry point for the Bash tool specifically.
//
// The credential pre-scan runs in <500ns (pre-compiled regexes, no allocation on match-fail path).
func (c *Classifier) ClassifyBash(toolName, commandText string) VerdictEntry {
	entry, _ := c.Classify(toolName)

	// Credential pattern pre-scan — runs BEFORE returning the entry.
	if hasCredentialPattern(commandText) {
		// Append EffectCredentialUse if not already present.
		if !effectsContain(entry.Effects, EffectCredentialUse) {
			newEffects := make([]string, len(entry.Effects)+1)
			copy(newEffects, entry.Effects)
			newEffects[len(entry.Effects)] = EffectCredentialUse
			entry.Effects = newEffects
		}
	}

	return entry
}

// hasCredentialPattern returns true if the command text matches any credential pattern.
// Uses pre-compiled regexes — no allocation on the non-match path.
func hasCredentialPattern(text string) bool {
	for _, re := range credentialPatterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

// effectsContain checks if effects slice contains the given effect.
// Zero-alloc, inline loop.
func effectsContain(effects []string, target string) bool {
	for _, e := range effects {
		if e == target {
			return true
		}
	}
	return false
}
