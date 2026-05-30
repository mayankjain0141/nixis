// SPDX-License-Identifier: MIT
package resource

import (
	"strings"

	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/pkg/aegis"
)

// pathRule maps a file path pattern to a SecurityLabel.
type pathRule struct {
	pattern  string // glob-style: "*" = any chars, prefix/suffix matching
	matchFn  func(path, pattern string) bool
	label    aegis.SecurityLabel
	category string // human-readable category for debugging
}

func (r *pathRule) matches(path string) bool {
	return r.matchFn(path, r.pattern)
}

// domainRule maps a domain/IP pattern to a SecurityLabel.
type domainRule struct {
	pattern  string
	matchFn  func(domain, pattern string) bool
	label    aegis.SecurityLabel
	category string
}

func (r *domainRule) matches(domain string) bool {
	return r.matchFn(domain, r.pattern)
}

// matchExact matches if path equals pattern exactly.
func matchExact(path, pattern string) bool {
	return path == pattern
}

// matchPrefix matches if path starts with pattern.
func matchPrefix(path, pattern string) bool {
	return strings.HasPrefix(path, pattern)
}

// matchSuffix matches if path ends with pattern.
func matchSuffix(path, pattern string) bool {
	return strings.HasSuffix(path, pattern)
}

// matchContains matches if path contains pattern.
func matchContains(path, pattern string) bool {
	return strings.Contains(path, pattern)
}

// highCredentialLabel is for high-sensitivity credential files.
func highCredentialLabel() aegis.SecurityLabel {
	return aegis.SecurityLabel{
		Confidentiality: 1000,
		Integrity:       500,
		Category:        ifc.CatCredentials,
	}
}

// highSecurityKeyLabel is for cryptographic key material.
func highSecurityKeyLabel() aegis.SecurityLabel {
	return aegis.SecurityLabel{
		Confidentiality: 1000,
		Integrity:       500,
		Category:        ifc.CatCredentials | ifc.CatSecurityKey,
	}
}

// mediumCredentialLabel is for moderate-sensitivity credential files.
func mediumCredentialLabel() aegis.SecurityLabel {
	return aegis.SecurityLabel{
		Confidentiality: 800,
		Integrity:       400,
		Category:        ifc.CatCredentials,
	}
}

// internalLabel is for internal-only resources.
func internalLabel() aegis.SecurityLabel {
	return aegis.SecurityLabel{
		Confidentiality: 300,
		Integrity:       300,
		Category:        ifc.CatInternal,
	}
}

// defaultPathRules returns the built-in path classification rules.
// Rules are evaluated in order — first match wins.
func defaultPathRules() []pathRule {
	return []pathRule{
		// System credential files
		{pattern: "/etc/shadow", matchFn: matchExact, label: highCredentialLabel(), category: "system-credentials"},
		{pattern: "/etc/passwd", matchFn: matchExact, label: highCredentialLabel(), category: "system-credentials"},
		{pattern: "/etc/sudoers", matchFn: matchExact, label: highCredentialLabel(), category: "system-credentials"},
		{pattern: "/etc/master.passwd", matchFn: matchExact, label: highCredentialLabel(), category: "system-credentials"},

		// SSH keys and config
		{pattern: "/.ssh/", matchFn: matchContains, label: highSecurityKeyLabel(), category: "ssh-keys"},
		{pattern: "id_rsa", matchFn: matchContains, label: highSecurityKeyLabel(), category: "ssh-keys"},
		{pattern: "id_ed25519", matchFn: matchContains, label: highSecurityKeyLabel(), category: "ssh-keys"},
		{pattern: "id_ecdsa", matchFn: matchContains, label: highSecurityKeyLabel(), category: "ssh-keys"},
		{pattern: "authorized_keys", matchFn: matchContains, label: highSecurityKeyLabel(), category: "ssh-keys"},

		// Cloud credentials
		{pattern: "/.aws/credentials", matchFn: matchContains, label: highSecurityKeyLabel(), category: "cloud-credentials"},
		{pattern: "/.aws/config", matchFn: matchContains, label: mediumCredentialLabel(), category: "cloud-config"},
		{pattern: "/.gcloud/", matchFn: matchContains, label: highSecurityKeyLabel(), category: "cloud-credentials"},
		{pattern: "/.azure/", matchFn: matchContains, label: highSecurityKeyLabel(), category: "cloud-credentials"},
		{pattern: "/.config/gcloud/", matchFn: matchContains, label: highSecurityKeyLabel(), category: "cloud-credentials"},

		// Kubernetes secrets
		{pattern: "/.kube/config", matchFn: matchContains, label: highSecurityKeyLabel(), category: "k8s-credentials"},
		{pattern: "/var/run/secrets/", matchFn: matchPrefix, label: highSecurityKeyLabel(), category: "k8s-secrets"},

		// Certificate/key material
		{pattern: ".pem", matchFn: matchSuffix, label: highSecurityKeyLabel(), category: "key-material"},
		{pattern: ".key", matchFn: matchSuffix, label: highSecurityKeyLabel(), category: "key-material"},
		{pattern: ".p12", matchFn: matchSuffix, label: highSecurityKeyLabel(), category: "key-material"},
		{pattern: ".pfx", matchFn: matchSuffix, label: highSecurityKeyLabel(), category: "key-material"},
		{pattern: ".jks", matchFn: matchSuffix, label: highSecurityKeyLabel(), category: "key-material"},
		{pattern: "/etc/ssl/private/", matchFn: matchPrefix, label: highSecurityKeyLabel(), category: "key-material"},
		{pattern: "/etc/pki/", matchFn: matchPrefix, label: highSecurityKeyLabel(), category: "key-material"},

		// Environment/secret files
		{pattern: ".env", matchFn: matchSuffix, label: mediumCredentialLabel(), category: "env-files"},
		{pattern: ".env.", matchFn: matchContains, label: mediumCredentialLabel(), category: "env-files"},
		{pattern: ".secret", matchFn: matchSuffix, label: mediumCredentialLabel(), category: "secret-files"},
		{pattern: "credentials.json", matchFn: matchContains, label: highSecurityKeyLabel(), category: "credential-files"},
		{pattern: "service-account", matchFn: matchContains, label: highSecurityKeyLabel(), category: "credential-files"},

		// Token/auth files
		{pattern: ".npmrc", matchFn: matchSuffix, label: mediumCredentialLabel(), category: "auth-tokens"},
		{pattern: ".pypirc", matchFn: matchSuffix, label: mediumCredentialLabel(), category: "auth-tokens"},
		{pattern: ".netrc", matchFn: matchSuffix, label: mediumCredentialLabel(), category: "auth-tokens"},
		{pattern: ".docker/config.json", matchFn: matchContains, label: mediumCredentialLabel(), category: "auth-tokens"},
		{pattern: "/.git-credentials", matchFn: matchContains, label: mediumCredentialLabel(), category: "auth-tokens"},

		// History files (contain sensitive commands)
		{pattern: ".bash_history", matchFn: matchSuffix, label: internalLabel(), category: "history"},
		{pattern: ".zsh_history", matchFn: matchSuffix, label: internalLabel(), category: "history"},

		// Database files
		{pattern: "/var/lib/mysql/", matchFn: matchPrefix, label: internalLabel(), category: "database"},
		{pattern: "/var/lib/postgresql/", matchFn: matchPrefix, label: internalLabel(), category: "database"},
	}
}

// defaultDomainRules returns the built-in domain classification rules.
func defaultDomainRules() []domainRule {
	return []domainRule{
		// Cloud metadata services — highest sensitivity
		{pattern: "169.254.169.254", matchFn: matchContains, label: highSecurityKeyLabel(), category: "cloud-metadata"},
		{pattern: "metadata.google.internal", matchFn: matchContains, label: highSecurityKeyLabel(), category: "cloud-metadata"},
		{pattern: "metadata.azure.com", matchFn: matchContains, label: highSecurityKeyLabel(), category: "cloud-metadata"},

		// Internal network indicators
		{pattern: "localhost", matchFn: matchContains, label: internalLabel(), category: "localhost"},
		{pattern: "127.0.0.1", matchFn: matchContains, label: internalLabel(), category: "localhost"},
		{pattern: "0.0.0.0", matchFn: matchContains, label: internalLabel(), category: "localhost"},
		{pattern: ".internal", matchFn: matchSuffix, label: internalLabel(), category: "internal-domain"},
		{pattern: ".local", matchFn: matchSuffix, label: internalLabel(), category: "internal-domain"},
	}
}

// defaultToolSinks returns tools that are always classified as external sinks.
func defaultToolSinks() map[string]bool {
	return map[string]bool{
		"WebFetch":    true,
		"WebSearch":   true,
		"SendMessage": true,
	}
}
