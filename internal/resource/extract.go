// SPDX-License-Identifier: MIT
package resource

import (
	"strings"
)

// ExtractPaths pulls file paths from tool arguments.
// Handles Read/Write "file_path"/"path", Bash commands with file targets.
func ExtractPaths(tool string, args map[string]any) []string {
	if args == nil {
		return nil
	}

	var paths []string

	switch tool {
	case "Read", "Write":
		if p := stringArg(args, "file_path"); p != "" {
			paths = append(paths, p)
		}
		if p := stringArg(args, "path"); p != "" {
			paths = append(paths, p)
		}
	case "Bash":
		cmd := stringArg(args, "command")
		if cmd != "" {
			paths = append(paths, extractPathsFromCommand(cmd)...)
		}
	case "Glob":
		if p := stringArg(args, "glob_pattern"); p != "" {
			paths = append(paths, p)
		}
	case "Grep":
		if p := stringArg(args, "path"); p != "" {
			paths = append(paths, p)
		}
	}

	return paths
}

// ExtractDomains pulls domains/URLs from tool arguments.
func ExtractDomains(tool string, args map[string]any) []string {
	if args == nil {
		return nil
	}

	var domains []string

	switch tool {
	case "WebFetch":
		if u := stringArg(args, "url"); u != "" {
			domains = append(domains, u)
		}
	case "WebSearch":
		if u := stringArg(args, "search_term"); u != "" {
			domains = append(domains, u)
		}
	case "Bash":
		cmd := stringArg(args, "command")
		if cmd != "" {
			domains = append(domains, extractURLsFromCommand(cmd)...)
		}
	}

	return domains
}

// stringArg safely extracts a string value from a map.
func stringArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// extractPathsFromCommand extracts file paths from shell commands.
// Looks for arguments to common file-reading commands.
func extractPathsFromCommand(cmd string) []string {
	tokens := strings.Fields(cmd)
	if len(tokens) == 0 {
		return nil
	}

	var paths []string

	// Direct file-reading commands: cat, head, tail, less, more, etc.
	fileReaders := map[string]bool{
		"cat": true, "head": true, "tail": true, "less": true, "more": true,
		"tac": true, "nl": true, "wc": true, "file": true, "stat": true,
		"md5sum": true, "sha256sum": true, "sha1sum": true, "xxd": true,
		"strings": true, "hexdump": true, "od": true,
	}

	// Look for file reader patterns: cmd [flags] <path>
	baseTool := baseCommand(tokens[0])
	if fileReaders[baseTool] {
		for _, t := range tokens[1:] {
			if !strings.HasPrefix(t, "-") && looksLikePath(t) {
				paths = append(paths, t)
			}
		}
	}

	// cp/scp source path
	if baseTool == "cp" || baseTool == "scp" || baseTool == "rsync" {
		for _, t := range tokens[1:] {
			if !strings.HasPrefix(t, "-") && looksLikePath(t) {
				paths = append(paths, t)
			}
		}
	}

	// Look for input redirection: < /path/to/file
	for i, t := range tokens {
		if t == "<" && i+1 < len(tokens) {
			paths = append(paths, tokens[i+1])
		}
	}

	// Piped commands: capture paths from the full command
	if strings.Contains(cmd, "|") {
		parts := strings.Split(cmd, "|")
		for _, part := range parts[1:] {
			subTokens := strings.Fields(strings.TrimSpace(part))
			if len(subTokens) == 0 {
				continue
			}
			subBase := baseCommand(subTokens[0])
			if fileReaders[subBase] {
				for _, t := range subTokens[1:] {
					if !strings.HasPrefix(t, "-") && looksLikePath(t) {
						paths = append(paths, t)
					}
				}
			}
		}
	}

	return paths
}

// extractURLsFromCommand extracts URLs and domains from shell commands.
func extractURLsFromCommand(cmd string) []string {
	tokens := strings.Fields(cmd)
	var urls []string

	for _, t := range tokens {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			urls = append(urls, t)
		}
		// Cloud metadata IP
		if strings.Contains(t, "169.254.169.254") {
			urls = append(urls, t)
		}
	}

	return urls
}

// baseCommand extracts the command name from a possible path (e.g., /usr/bin/cat -> cat).
func baseCommand(cmd string) string {
	idx := strings.LastIndex(cmd, "/")
	if idx >= 0 {
		return cmd[idx+1:]
	}
	return cmd
}

// looksLikePath returns true if a token looks like a file path.
func looksLikePath(s string) bool {
	if s == "" {
		return false
	}
	// Absolute or relative paths
	if s[0] == '/' || s[0] == '~' || s[0] == '.' {
		return true
	}
	// Contains path separators with at least one directory
	if strings.Contains(s, "/") && !strings.HasPrefix(s, "http") {
		return true
	}
	// Known sensitive filenames
	sensitiveNames := []string{
		".env", ".pem", ".key", "shadow", "passwd", "credentials",
		"id_rsa", "id_ed25519", "authorized_keys", ".secret",
	}
	for _, name := range sensitiveNames {
		if strings.Contains(s, name) {
			return true
		}
	}
	return false
}
