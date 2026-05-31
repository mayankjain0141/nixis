// SPDX-License-Identifier: MIT
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

// SelfProtectGuard is a hardcoded security guard compiled into the daemon binary.
// It runs BEFORE any YAML/CEL policy evaluation and cannot be disabled by editing
// policy files. It blocks tool calls that target Nixis's own configuration, binaries,
// policies, or service management.
//
// This guard only fires on tool calls routed through the hook (agent actions).
// Human users editing files directly in their terminal are never affected because
// their actions do not pass through the hook.
type SelfProtectGuard struct {
	homeDir        string
	protectedPaths []string
	shellPatterns  []*regexp.Regexp
	initOnce       sync.Once
}

// NewSelfProtectGuard creates a guard using the current user's home directory.
func NewSelfProtectGuard() *SelfProtectGuard {
	g := &SelfProtectGuard{}
	g.init()
	return g
}

func (g *SelfProtectGuard) init() {
	g.initOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "/tmp"
		}
		g.homeDir = home

		g.protectedPaths = []string{
			filepath.Join(home, ".nixis") + string(filepath.Separator),
			filepath.Join(home, ".nixis"),
			filepath.Join(home, ".claude", "settings.json"),
			filepath.Join(home, "Library", "LaunchAgents", "com.nixis.daemon.plist"),
			filepath.Join(home, ".config", "systemd", "user", "nixis-daemon.service"),
		}

		g.shellPatterns = []*regexp.Regexp{
			regexp.MustCompile(`(?i)\bnixis\b.*\b(daemon|setup)\b.*\b(stop|restart|uninstall|remove)\b`),
			regexp.MustCompile(`(?i)\b(kill|pkill|killall)\b.*nixis`),
			regexp.MustCompile(`(?i)\blaunchctl\b.*(bootout|unload|remove).*nixis`),
			regexp.MustCompile(`(?i)\bsystemctl\b.*(stop|disable|mask).*nixis`),
			regexp.MustCompile(`(?i)\b(rm|mv|chmod|chown)\b.*[/.]nixis`),
			regexp.MustCompile(`(?i)\b(rm|mv|chmod|chown)\b.*settings\.json`),
			regexp.MustCompile(`(?i)(echo|cat|tee|sed|awk).*>.*[/.]nixis`),
			regexp.MustCompile(`(?i)\bcrontab\b.*nixis`),
			regexp.MustCompile(`(?i)\bgit\b.*\b(checkout|reset|clean)\b.*[/.]nixis`),
			regexp.MustCompile(`(?i)cd\s+.*[/.]nixis.*&&`),
		}
	})
}

const selfProtectDenyReason = "Nixis self-protection: AI agents cannot modify governance configuration. " +
	"To change policies, edit ~/.nixis/policies/custom/ directly in your terminal. " +
	"To manage the daemon, run 'nixis daemon stop' in your terminal."

// Check evaluates a CheckRequest against the self-protection rules.
// Returns a non-nil Decision if the request is blocked, nil if it should proceed
// to normal policy evaluation.
func (g *SelfProtectGuard) Check(req nixis.CheckRequest) *nixis.Decision {
	if g.checkFilePath(req) {
		return &nixis.Decision{
			Action:   nixis.ActionDeny,
			Reason:   selfProtectDenyReason,
			PolicyID: "nixis-self-protection-guard",
		}
	}

	if g.checkShellCommand(req) {
		return &nixis.Decision{
			Action:   nixis.ActionDeny,
			Reason:   selfProtectDenyReason,
			PolicyID: "nixis-self-protection-guard",
		}
	}

	return nil
}

// checkFilePath inspects tool calls that write files (Write, Edit, etc.)
// and blocks writes to protected paths. Resolves symlinks before matching.
func (g *SelfProtectGuard) checkFilePath(req nixis.CheckRequest) bool {
	path := g.extractFilePath(req)
	if path == "" {
		return false
	}

	resolved := g.resolvePath(path)
	return g.isProtectedPath(resolved)
}

// checkShellCommand inspects Shell/Bash tool calls for commands that
// target Nixis processes or configuration.
func (g *SelfProtectGuard) checkShellCommand(req nixis.CheckRequest) bool {
	cmd := g.extractCommand(req)
	if cmd == "" {
		return false
	}

	for _, pattern := range g.shellPatterns {
		if pattern.MatchString(cmd) {
			return true
		}
	}

	return g.commandTargetsProtectedPath(cmd)
}

// extractFilePath gets the file path from tool arguments.
// Supports Write, Edit, StrReplace, MultiEdit tool formats.
func (g *SelfProtectGuard) extractFilePath(req nixis.CheckRequest) string {
	if len(req.Args) == 0 {
		return ""
	}

	fileTools := map[string]bool{
		"Write": true, "write": true,
		"Edit": true, "edit": true,
		"StrReplace": true, "str_replace": true,
		"MultiEdit": true, "multi_edit": true,
		"Delete": true, "delete": true,
	}

	if !fileTools[req.Tool] {
		return ""
	}

	var args struct {
		Path     string `json:"path"`
		FilePath string `json:"file_path"`
		Target   string `json:"target_file"`
	}
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return ""
	}

	if args.Path != "" {
		return args.Path
	}
	if args.FilePath != "" {
		return args.FilePath
	}
	return args.Target
}

// extractCommand gets the shell command from tool arguments.
func (g *SelfProtectGuard) extractCommand(req nixis.CheckRequest) string {
	shellTools := map[string]bool{
		"Shell": true, "shell": true,
		"Bash": true, "bash": true,
		"Terminal": true, "terminal": true,
	}

	if !shellTools[req.Tool] {
		return ""
	}

	if len(req.Args) == 0 {
		return ""
	}

	var args struct {
		Command string `json:"command"`
		Cmd     string `json:"cmd"`
		Input   string `json:"input"`
	}
	if err := json.Unmarshal(req.Args, &args); err != nil {
		return ""
	}

	if args.Command != "" {
		return args.Command
	}
	if args.Cmd != "" {
		return args.Cmd
	}
	return args.Input
}

// resolvePath expands ~ and resolves symlinks to get the real target path.
func (g *SelfProtectGuard) resolvePath(path string) string {
	if strings.HasPrefix(path, "~/") {
		path = filepath.Join(g.homeDir, path[2:])
	}
	if strings.HasPrefix(path, "$HOME/") {
		path = filepath.Join(g.homeDir, path[6:])
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// If symlink resolution fails (file doesn't exist yet),
		// resolve as much of the parent path as possible.
		dir := filepath.Dir(path)
		resolvedDir, dirErr := filepath.EvalSymlinks(dir)
		if dirErr == nil {
			return filepath.Join(resolvedDir, filepath.Base(path))
		}
		return filepath.Clean(path)
	}
	return resolved
}

// isProtectedPath checks if a resolved path falls within any protected location.
func (g *SelfProtectGuard) isProtectedPath(resolved string) bool {
	for _, protected := range g.protectedPaths {
		if strings.HasSuffix(protected, string(filepath.Separator)) {
			if strings.HasPrefix(resolved, protected) {
				return true
			}
		} else {
			if resolved == protected {
				return true
			}
		}
	}
	return false
}

// commandTargetsProtectedPath checks if a shell command contains references
// to protected paths that aren't caught by the regex patterns alone.
func (g *SelfProtectGuard) commandTargetsProtectedPath(cmd string) bool {
	pathIndicators := []string{
		".nixis/",
		".nixis\"",
		".nixis'",
		"nixis.sock",
		"com.nixis.daemon",
		"nixis-daemon.service",
		".claude/settings.json",
	}

	cmdLower := strings.ToLower(cmd)
	for _, indicator := range pathIndicators {
		if strings.Contains(cmdLower, indicator) {
			destructiveVerbs := []string{
				"rm ", "mv ", "cp ", "chmod ", "chown ",
				"echo ", "cat ", "tee ", "sed ", "awk ",
				"truncate ", "shred ",
				"> ", ">> ",
			}
			for _, verb := range destructiveVerbs {
				if strings.Contains(cmdLower, verb) {
					return true
				}
			}
		}
	}
	return false
}
