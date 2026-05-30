// SPDX-License-Identifier: MIT
// Package label wraps internal/resource with daemon-derived LabeledRequest metadata
// for CEL variable exposure. It does NOT participate in Dominates() enforcement.
package label

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/mayjain/aegis/internal/classify"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/internal/resource"
	"github.com/mayjain/aegis/pkg/aegis"
)

// LabeledRequest is the output of Label(). Contains resource classification
// with match metadata for CEL fallback policies.
type LabeledRequest struct {
	// Matched is true if ANY path/domain rule fired. When false, CEL fallback
	// policies can apply stricter handling via !resource_matched.
	Matched bool

	// ResourceLabel is the derived SecurityLabel (may be zero if !Matched).
	ResourceLabel aegis.SecurityLabel

	// AllResourceLabels contains labels for ALL extracted paths/domains.
	// Used when a single command touches multiple resources (e.g., cp a b).
	AllResourceLabels []aegis.SecurityLabel

	// ResourceType classifies the primary resource kind.
	// Values: "file", "url", "credential", "cloud_metadata", "kernel_special", "unknown"
	ResourceType string

	// ResourcePath is the first extracted path/URL (for audit/CEL access).
	ResourcePath string

	// ResourcePaths contains ALL extracted paths/URLs for multi-resource commands.
	ResourcePaths []string

	// ContainsNetworkCmd is true if a Bash command contains a network-capable binary.
	ContainsNetworkCmd bool
}

// Labeler derives LabeledRequest from a CheckRequest.
// This is the CEL-aware wrapper around internal/resource.ResourceLabeler.
type Labeler interface {
	Label(req aegis.CheckRequest, verdict classify.VerdictEntry) LabeledRequest
}

// ruleBasedLabeler wraps resource.RuleBasedLabeler with CEL metadata.
type ruleBasedLabeler struct {
	inner       *resource.RuleBasedLabeler
	pathRules   []extPathRule
	domainRules []extDomainRule
}

// NewLabeler creates a Labeler that wraps the standard RuleBasedLabeler.
func NewLabeler() Labeler {
	return &ruleBasedLabeler{
		inner:       resource.NewRuleBasedLabeler(),
		pathRules:   extDefaultPathRules(),
		domainRules: extDefaultDomainRules(),
	}
}

// Label derives resource labels and match metadata from tool+args.
func (l *ruleBasedLabeler) Label(req aegis.CheckRequest, _ classify.VerdictEntry) LabeledRequest {
	var decodedArgs map[string]any
	if len(req.Args) > 0 {
		_ = json.Unmarshal(req.Args, &decodedArgs)
	}

	// Extract paths: use the resource package for standard tools, plus broader Bash extraction.
	paths := resource.ExtractPaths(req.Tool, decodedArgs)
	if req.Tool == "Bash" {
		if cmd, ok := decodedArgs["command"].(string); ok {
			paths = mergePaths(paths, extractBashPaths(cmd))
		}
	}
	domains := resource.ExtractDomains(req.Tool, decodedArgs)

	// allRaw combines paths and domains for ResourcePaths/ResourcePath reporting.
	var allRaw []string
	allRaw = append(allRaw, paths...)
	allRaw = append(allRaw, domains...)

	var allLabels []aegis.SecurityLabel
	var allTypes []string
	var matched bool

	for _, p := range paths {
		lbl, rtype, ok := l.classifyPath(p)
		allLabels = append(allLabels, lbl)
		allTypes = append(allTypes, rtype)
		if ok {
			matched = true
		}
	}
	for _, d := range domains {
		lbl, rtype, ok := l.classifyDomain(d)
		allLabels = append(allLabels, lbl)
		allTypes = append(allTypes, rtype)
		if ok {
			matched = true
		}
	}

	joined := joinAll(allLabels)

	// Primary resource type: first non-unknown type found.
	primaryType := "unknown"
	for _, rt := range allTypes {
		if rt != "unknown" {
			primaryType = rt
			break
		}
	}

	// For WebFetch/WebSearch with no matched domain rule, return "url" as the resource type.
	if !matched && primaryType == "unknown" {
		if len(domains) > 0 && (req.Tool == "WebFetch" || req.Tool == "WebSearch") {
			primaryType = "url"
		}
	}

	var resourcePath string
	if len(allRaw) > 0 {
		resourcePath = allRaw[0]
	}

	result := LabeledRequest{
		Matched:           matched,
		ResourceLabel:     joined,
		AllResourceLabels: allLabels,
		ResourceType:      primaryType,
		ResourcePath:      resourcePath,
		ResourcePaths:     allRaw,
	}

	if req.Tool == "Bash" {
		if cmd, ok := decodedArgs["command"].(string); ok {
			result.ContainsNetworkCmd = containsNetworkCmd(cmd)
		}
	}

	return result
}

// extractBashPaths does broad path extraction from a Bash command, covering commands
// not handled by resource.ExtractPaths (e.g., ls, chmod, find).
func extractBashPaths(cmd string) []string {
	tokens := strings.Fields(cmd)
	if len(tokens) == 0 {
		return nil
	}

	broadCmds := map[string]bool{
		"ls": true, "ll": true, "dir": true, "chmod": true, "chown": true,
		"find": true, "touch": true, "mkdir": true, "rmdir": true, "rm": true,
		"mv": true, "cp": true, "ln": true, "stat": true, "file": true,
	}

	var paths []string
	base := baseCommand(tokens[0])
	if broadCmds[base] {
		for _, t := range tokens[1:] {
			if strings.HasPrefix(t, "-") {
				continue
			}
			if looksLikePathToken(t) {
				paths = append(paths, t)
			}
		}
	}

	return paths
}

// looksLikePathToken returns true if a shell token looks like a file path.
func looksLikePathToken(s string) bool {
	if s == "" {
		return false
	}
	return s[0] == '/' || s[0] == '~' || s[0] == '.'
}

// mergePaths appends b to a, deduplicating exact matches.
func mergePaths(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a))
	for _, p := range a {
		seen[p] = true
	}
	result := a
	for _, p := range b {
		if !seen[p] {
			seen[p] = true
			result = append(result, p)
		}
	}
	return result
}

// joinAll joins a slice of SecurityLabels using max(Conf), min(Integrity), union(Category).
func joinAll(labels []aegis.SecurityLabel) aegis.SecurityLabel {
	if len(labels) == 0 {
		return aegis.SecurityLabel{}
	}
	result := labels[0]
	for _, l := range labels[1:] {
		result = ifc.Join(result, l)
	}
	return result
}

// extPathRule is the label package's own path rule with ResourceType.
type extPathRule struct {
	pattern string
	matchFn func(path, pattern string) bool
	label   aegis.SecurityLabel
	rtype   string
}

func (r *extPathRule) matches(path string) bool {
	return r.matchFn(path, r.pattern)
}

// extDomainRule is the label package's own domain rule with ResourceType.
type extDomainRule struct {
	pattern string
	matchFn func(domain, pattern string) bool
	label   aegis.SecurityLabel
	rtype   string
}

func (r *extDomainRule) matches(domain string) bool {
	return r.matchFn(domain, r.pattern)
}

// classifyPath classifies a file path using the extended rule set.
// Returns (label, resourceType, matched).
func (l *ruleBasedLabeler) classifyPath(path string) (aegis.SecurityLabel, string, bool) {
	for i := range l.pathRules {
		if l.pathRules[i].matches(path) {
			return l.pathRules[i].label, l.pathRules[i].rtype, true
		}
	}
	return aegis.SecurityLabel{}, "unknown", false
}

// classifyDomain classifies a URL/domain using the extended rule set.
// Returns (label, resourceType, matched).
func (l *ruleBasedLabeler) classifyDomain(domain string) (aegis.SecurityLabel, string, bool) {
	for i := range l.domainRules {
		if l.domainRules[i].matches(domain) {
			return l.domainRules[i].label, l.domainRules[i].rtype, true
		}
	}
	return aegis.SecurityLabel{}, "unknown", false
}

func matchExact(path, pattern string) bool    { return path == pattern }
func matchPrefix(path, pattern string) bool   { return strings.HasPrefix(path, pattern) }
func matchSuffix(path, pattern string) bool   { return strings.HasSuffix(path, pattern) }
func matchContains(path, pattern string) bool { return strings.Contains(path, pattern) }

var (
	reProcPIDEnviron = regexp.MustCompile(`/proc/[0-9]+/environ`)
	reProcPIDMem     = regexp.MustCompile(`/proc/[0-9]+/mem`)
	reProcPIDMaps    = regexp.MustCompile(`/proc/[0-9]+/maps`)
)

func matchRegex(re *regexp.Regexp) func(string, string) bool {
	return func(path, _ string) bool {
		return re.MatchString(path)
	}
}

func lbl(conf, integ uint16, cat uint32) aegis.SecurityLabel {
	return aegis.SecurityLabel{Confidentiality: conf, Integrity: integ, Category: cat}
}

// extDefaultPathRules returns the label package's extended path classification rules.
// Rules are evaluated in order — first match wins.
func extDefaultPathRules() []extPathRule {
	const (
		credType   = "credential"
		kernelType = "kernel_special"
		fileType   = "file"
	)
	return []extPathRule{
		// High-sensitivity system credentials (conf=2000)
		{pattern: "/etc/shadow", matchFn: matchExact,
			label: lbl(2000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: "/etc/gshadow", matchFn: matchExact,
			label: lbl(2000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: "/etc/sudoers", matchFn: matchExact,
			label: lbl(2000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: "/etc/sudoers.d/", matchFn: matchPrefix,
			label: lbl(2000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: "/etc/passwd", matchFn: matchExact,
			label: lbl(2000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: "/etc/master.passwd", matchFn: matchExact,
			label: lbl(2000, 500, ifc.CatCredentials), rtype: credType},
		// /proc/<pid>/environ regex
		{"", matchRegex(reProcPIDEnviron),
			lbl(2000, 500, ifc.CatCredentials), credType},
		// /proc/<pid>/mem regex (credentials + security key)
		{"", matchRegex(reProcPIDMem),
			lbl(2000, 500, ifc.CatCredentials|ifc.CatSecurityKey), kernelType},
		// /proc/<pid>/maps regex
		{"", matchRegex(reProcPIDMaps),
			lbl(2000, 500, ifc.CatCredentials), credType},
		// Kernel memory devices (conf=2000, CatSecurityKey)
		{pattern: "/dev/mem", matchFn: matchExact,
			label: lbl(2000, 500, ifc.CatSecurityKey), rtype: kernelType},
		{pattern: "/dev/kmem", matchFn: matchExact,
			label: lbl(2000, 500, ifc.CatSecurityKey), rtype: kernelType},
		{pattern: "/dev/port", matchFn: matchExact,
			label: lbl(2000, 500, ifc.CatSecurityKey), rtype: kernelType},

		// Cryptographic key material (conf=1500, CatCredentials|CatSecurityKey)
		{pattern: "/.ssh/", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "id_rsa", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "id_ed25519", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "id_ecdsa", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "authorized_keys", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "/.aws/credentials", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "/.gnupg/", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "/.config/gcloud/", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "/.azure/", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "/.gcloud/", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "/.kube/config", matchFn: matchContains,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "/var/run/secrets/", matchFn: matchPrefix,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "/etc/ssl/private/", matchFn: matchPrefix,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},
		{pattern: "/etc/pki/", matchFn: matchPrefix,
			label: lbl(1500, 500, ifc.CatCredentials|ifc.CatSecurityKey), rtype: credType},

		// Credential files (conf=1000, CatCredentials)
		{pattern: ".env", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".env.", matchFn: matchContains,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".pem", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".key", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".p12", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".pfx", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".jks", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: "/.docker/config.json", matchFn: matchContains,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".npmrc", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".pypirc", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".netrc", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: "/.git-credentials", matchFn: matchContains,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: ".secret", matchFn: matchSuffix,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: "credentials.json", matchFn: matchContains,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},
		{pattern: "service-account", matchFn: matchContains,
			label: lbl(1000, 500, ifc.CatCredentials), rtype: credType},

		// Sensitive logs (conf=800, CatPersonalData|CatSecurityKey)
		{pattern: "/var/log/audit/", matchFn: matchPrefix,
			label: lbl(800, 400, ifc.CatPersonalData|ifc.CatSecurityKey), rtype: fileType},
		// Sensitive logs (conf=500, CatPersonalData)
		{pattern: "/var/log/", matchFn: matchPrefix,
			label: lbl(500, 300, ifc.CatPersonalData), rtype: fileType},

		// Source code files (conf=100, CatInternal)
		{pattern: ".go", matchFn: matchSuffix,
			label: lbl(100, 300, ifc.CatInternal), rtype: fileType},
		{pattern: ".py", matchFn: matchSuffix,
			label: lbl(100, 300, ifc.CatInternal), rtype: fileType},
		{pattern: ".js", matchFn: matchSuffix,
			label: lbl(100, 300, ifc.CatInternal), rtype: fileType},
		{pattern: ".ts", matchFn: matchSuffix,
			label: lbl(100, 300, ifc.CatInternal), rtype: fileType},

		// Temp/safe (conf=0, matched=true, ResourceType="file")
		// Match both "/tmp/" prefix (for paths under /tmp/) and "/tmp" exact (for ls /tmp).
		{pattern: "/tmp", matchFn: matchPrefix,
			label: lbl(0, 0, 0), rtype: fileType},
		{pattern: "/var/tmp", matchFn: matchPrefix,
			label: lbl(0, 0, 0), rtype: fileType},
	}
}

// extDefaultDomainRules returns the label package's extended domain classification rules.
func extDefaultDomainRules() []extDomainRule {
	const (
		cloudMetaType = "cloud_metadata"
		urlType       = "url"
	)
	return []extDomainRule{
		// Cloud metadata services (conf=2000, CatSecurityKey)
		{pattern: "169.254.169.254", matchFn: matchContains,
			label: lbl(2000, 500, ifc.CatSecurityKey), rtype: cloudMetaType},
		{pattern: "metadata.google.internal", matchFn: matchContains,
			label: lbl(2000, 500, ifc.CatSecurityKey), rtype: cloudMetaType},
		{pattern: "100.100.100.200", matchFn: matchContains,
			label: lbl(2000, 500, ifc.CatSecurityKey), rtype: cloudMetaType},
		{pattern: "metadata.azure.com", matchFn: matchContains,
			label: lbl(2000, 500, ifc.CatSecurityKey), rtype: cloudMetaType},
		{pattern: "fd00:ec2::254", matchFn: matchContains,
			label: lbl(2000, 500, ifc.CatSecurityKey), rtype: cloudMetaType},

		// Internal domains (conf=500, CatInternal)
		{pattern: ".internal", matchFn: matchSuffix,
			label: lbl(500, 300, ifc.CatInternal), rtype: urlType},
		{pattern: ".corp", matchFn: matchSuffix,
			label: lbl(500, 300, ifc.CatInternal), rtype: urlType},
		{pattern: ".local", matchFn: matchSuffix,
			label: lbl(500, 300, ifc.CatInternal), rtype: urlType},
	}
}

// networkBinaries is the set of network-capable binary names.
var networkBinaries = map[string]bool{
	"curl":     true,
	"wget":     true,
	"nc":       true,
	"ncat":     true,
	"netcat":   true,
	"socat":    true,
	"telnet":   true,
	"ftp":      true,
	"sftp":     true,
	"ssh":      true,
	"scp":      true,
	"rsync":    true,
	"rclone":   true,
	"s3cmd":    true,
	"openssl":  true,
	"nmap":     true,
	"aws":      true,
	"gcloud":   true,
	"az":       true,
	"kubectl":  true,
	"git":      true,
	"dig":      true,
	"nslookup": true,
	"host":     true,
}

// containsNetworkCmd returns true if any token in the command is a network-capable binary.
func containsNetworkCmd(command string) bool {
	tokens := strings.Fields(command)
	for _, t := range tokens {
		if networkBinaries[baseCommand(t)] {
			return true
		}
	}
	return false
}

// baseCommand extracts the command name from a possible path (/usr/bin/curl → curl).
func baseCommand(cmd string) string {
	idx := strings.LastIndex(cmd, "/")
	if idx >= 0 {
		return cmd[idx+1:]
	}
	return cmd
}
