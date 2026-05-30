// SPDX-License-Identifier: MIT
package resource

import (
	"strings"
)

// commandIsSink returns true if the shell command targets an external network destination.
// Used to classify Bash commands as sinks when the session is tainted.
func commandIsSink(cmd string) bool {
	tokens := strings.Fields(cmd)
	if len(tokens) == 0 {
		return false
	}

	// Network tools that send data externally
	networkTools := map[string]bool{
		"curl":    true,
		"wget":    true,
		"nc":      true,
		"ncat":    true,
		"netcat":  true,
		"ssh":     true,
		"scp":     true,
		"sftp":    true,
		"rsync":   true,
		"ftp":     true,
		"telnet":  true,
		"nmap":    true,
		"socat":   true,
		"openssl": true, // s_client can exfiltrate
	}

	// Check each token and piped segment for network tools.
	// Exception: curl/wget targeting only internal URLs are not sinks.
	segments := splitPipeline(cmd)
	for _, seg := range segments {
		segTokens := strings.Fields(seg)
		if len(segTokens) == 0 {
			continue
		}
		base := baseCommand(segTokens[0])
		if networkTools[base] {
			// If the only URL arguments are internal, do not classify as sink.
			if hasOnlyInternalURLs(segTokens[1:]) {
				continue
			}
			return true
		}
	}

	// Python/ruby/perl with socket usage
	interpreters := map[string]bool{
		"python": true, "python3": true, "python2": true,
		"ruby": true, "perl": true, "node": true,
	}
	base := baseCommand(tokens[0])
	if interpreters[base] {
		if strings.Contains(cmd, "socket") ||
			strings.Contains(cmd, "http") ||
			strings.Contains(cmd, "urllib") ||
			strings.Contains(cmd, "requests") ||
			strings.Contains(cmd, "connect") {
			return true
		}
	}

	// Check for URLs in any position (indicates external communication)
	for _, t := range tokens {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			// Allow internal URLs
			if !isInternalURL(t) {
				return true
			}
		}
	}

	// Data-binary or POST patterns (sending data externally)
	if strings.Contains(cmd, "--data") || strings.Contains(cmd, "--upload") ||
		strings.Contains(cmd, "-d ") || strings.Contains(cmd, "-F ") {
		return true
	}

	return false
}

// splitPipeline splits a command by pipes, semicolons, and && / ||.
func splitPipeline(cmd string) []string {
	// Simple split — handles the common cases
	var segments []string
	current := cmd

	for _, sep := range []string{"&&", "||", "|", ";"} {
		var newSegments []string
		parts := strings.Split(current, sep)
		newSegments = append(newSegments, parts...)
		if len(segments) == 0 {
			segments = newSegments
		} else {
			var expanded []string
			for _, s := range segments {
				parts = strings.Split(s, sep)
				expanded = append(expanded, parts...)
			}
			segments = expanded
		}
	}

	if len(segments) == 0 {
		return []string{cmd}
	}

	result := make([]string, 0, len(segments))
	for _, s := range segments {
		trimmed := strings.TrimSpace(s)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// hasOnlyInternalURLs returns true when every http/https token in args
// is an internal URL, OR there are no http/https tokens at all.
// Used to exempt curl/wget calls to localhost from sink classification.
func hasOnlyInternalURLs(args []string) bool {
	found := false
	for _, t := range args {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			found = true
			if !isInternalURL(t) {
				return false
			}
		}
	}
	return found
}

// isInternalURL returns true if the URL targets a known-internal host.
func isInternalURL(url string) bool {
	lower := strings.ToLower(url)
	internalPatterns := []string{
		"localhost", "127.0.0.1", "0.0.0.0",
		".internal", ".local", "::1",
	}
	for _, p := range internalPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}
