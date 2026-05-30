// SPDX-License-Identifier: MIT
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mayankjain0141/nixis/pkg/nixis"
)

func TestSelfProtectGuard_AllowedRequests(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	tests := []struct {
		name string
		tool string
		args map[string]any
	}{
		{name: "shell ls", tool: "Shell", args: map[string]any{"command": "ls"}},
		{name: "write to tmp", tool: "Write", args: map[string]any{"path": "/tmp/foo.txt"}},
		{name: "shell git status", tool: "Shell", args: map[string]any{"command": "git status"}},
		{name: "read nixis file allowed", tool: "Read", args: map[string]any{"path": "/Users/test/.nixis/policies/builtin/foo.yaml"}},
		{name: "shell echo to normal file", tool: "Bash", args: map[string]any{"command": "echo hello > /tmp/out.txt"}},
		{name: "shell kill other process", tool: "Bash", args: map[string]any{"command": "kill 12345"}},
		{name: "write to project file", tool: "Write", args: map[string]any{"path": "/home/user/project/src/main.go"}},
		{name: "shell npm install", tool: "Shell", args: map[string]any{"command": "npm install express"}},
		{name: "shell rm normal file", tool: "Bash", args: map[string]any{"command": "rm /tmp/foo.txt"}},
		{name: "empty args write", tool: "Write", args: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var argsJSON json.RawMessage
			if tt.args != nil {
				argsJSON, _ = json.Marshal(tt.args)
			}
			req := nixis.CheckRequest{Tool: tt.tool, Args: argsJSON}
			decision := g.Check(req)
			if decision != nil {
				t.Errorf("expected allow (nil), got deny: %s", decision.Reason)
			}
		})
	}
}

func TestSelfProtectGuard_BlocksFileWrites(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()
	home, _ := os.UserHomeDir()

	tests := []struct {
		name string
		tool string
		args map[string]any
	}{
		{
			name: "write to nixis policy builtin",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".nixis/policies/builtin/x.yaml")},
		},
		{
			name: "write to nixis hook binary",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".nixis/nixis-hook")},
		},
		{
			name: "write to settings.json",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".claude/settings.json")},
		},
		{
			name: "write to launchd plist",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, "Library/LaunchAgents/com.nixis.daemon.plist")},
		},
		{
			name: "write to systemd service",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".config/systemd/user/nixis-daemon.service")},
		},
		{
			name: "delete nixis hook",
			tool: "Delete",
			args: map[string]any{"path": filepath.Join(home, ".nixis/nixis-hook")},
		},
		{
			name: "edit nixis policy",
			tool: "Edit",
			args: map[string]any{"path": filepath.Join(home, ".nixis/policies/builtin/self-protection.yaml")},
		},
		{
			name: "str_replace settings",
			tool: "StrReplace",
			args: map[string]any{"path": filepath.Join(home, ".claude/settings.json")},
		},
		{
			name: "multi_edit nixis config",
			tool: "MultiEdit",
			args: map[string]any{"target_file": filepath.Join(home, ".nixis/config.yaml")},
		},
		{
			name: "tilde path write",
			tool: "Write",
			args: map[string]any{"path": "~/.nixis/policies/custom/evil.yaml"},
		},
		{
			name: "HOME var path write",
			tool: "Write",
			args: map[string]any{"path": "$HOME/.nixis/policies/x.yaml"},
		},
		{
			name: "tilde settings write",
			tool: "Write",
			args: map[string]any{"path": "~/.claude/settings.json"},
		},
		{
			name: "HOME var settings write",
			tool: "Write",
			args: map[string]any{"path": "$HOME/.claude/settings.json"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			argsJSON, _ := json.Marshal(tt.args)
			req := nixis.CheckRequest{Tool: tt.tool, Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Fatal("expected deny, got allow (nil)")
			}
			if decision.Action != nixis.ActionDeny {
				t.Errorf("expected ActionDeny, got %v", decision.Action)
			}
			if decision.PolicyID != "nixis-self-protection-guard" {
				t.Errorf("expected PolicyID 'nixis-self-protection-guard', got %q", decision.PolicyID)
			}
			if decision.Reason != selfProtectDenyReason {
				t.Errorf("unexpected reason: %s", decision.Reason)
			}
		})
	}
}

func TestSelfProtectGuard_BlocksShellCommands(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	tests := []struct {
		name    string
		command string
	}{
		{name: "kill pgrep nixis", command: "kill $(pgrep nixis)"},
		{name: "kill pgrep nixis-daemon", command: "kill $(pgrep nixis-daemon)"},
		{name: "pkill nixis-daemon", command: "pkill -9 nixis-daemon"},
		{name: "killall nixis-daemon", command: "killall nixis-daemon"},
		{name: "launchctl bootout", command: "launchctl bootout gui/501 com.nixis.daemon"},
		{name: "launchctl unload", command: "launchctl unload ~/Library/LaunchAgents/com.nixis.daemon.plist"},
		{name: "launchctl remove", command: "launchctl remove com.nixis.daemon"},
		{name: "systemctl stop", command: "systemctl --user stop nixis-daemon"},
		{name: "systemctl disable", command: "systemctl --user disable nixis-daemon"},
		{name: "systemctl mask", command: "systemctl --user mask nixis-daemon"},
		{name: "rm nixis dir", command: "rm -rf ~/.nixis/"},
		{name: "rm nixis hook", command: "rm ~/.nixis/nixis-hook"},
		{name: "mv nixis hook", command: "mv ~/.nixis/nixis-hook /tmp/"},
		{name: "chmod nixis hook", command: "chmod 000 ~/.nixis/nixis-hook"},
		{name: "chown nixis dir", command: "chown root:root ~/.nixis/"},
		{name: "nixis daemon stop", command: "nixis daemon stop"},
		{name: "nixis daemon restart", command: "nixis daemon restart"},
		{name: "nixis setup uninstall", command: "nixis setup --uninstall"},
		{name: "echo redirect to nixis", command: "echo 'exit 0' > ~/.nixis/nixis-hook"},
		{name: "tee to nixis", command: "echo '' | tee ~/.nixis/policies/builtin/allow-all.yaml"},
		{name: "sed on settings", command: "sed -i '' '/hooks/d' ~/.claude/settings.json"},
		{name: "crontab nixis kill", command: "echo '* * * * * kill $(pgrep nixis-daemon)' | crontab -"},
		{name: "crontab rm nixis", command: "crontab -l | echo '0 0 * * * rm -rf ~/.nixis' | crontab -"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			argsJSON, _ := json.Marshal(map[string]string{"command": tt.command})
			req := nixis.CheckRequest{Tool: "Bash", Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Fatalf("command %q: expected deny, got allow", tt.command)
			}
			if decision.Action != nixis.ActionDeny {
				t.Errorf("expected ActionDeny, got %v", decision.Action)
			}
		})
	}
}

func TestSelfProtectGuard_EvasionAttempts(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()
	home, _ := os.UserHomeDir()

	t.Run("symlink to protected dir", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		symlinkPath := filepath.Join(tmpDir, "innocent-link")
		targetPath := filepath.Join(home, ".nixis", "policies")

		if _, err := os.Stat(targetPath); err == nil {
			if err := os.Symlink(targetPath, symlinkPath); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}

			argsJSON, _ := json.Marshal(map[string]string{"path": filepath.Join(symlinkPath, "evil.yaml")})
			req := nixis.CheckRequest{Tool: "Write", Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Error("symlink evasion to .nixis/policies/: expected deny, got allow")
			}
		} else {
			t.Skip("target path does not exist")
		}
	})

	t.Run("symlink to settings.json", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		symlinkPath := filepath.Join(tmpDir, "link-to-settings")
		targetPath := filepath.Join(home, ".claude", "settings.json")

		if _, err := os.Stat(targetPath); err == nil {
			if err := os.Symlink(targetPath, symlinkPath); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}

			argsJSON, _ := json.Marshal(map[string]string{"path": symlinkPath})
			req := nixis.CheckRequest{Tool: "Write", Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Error("symlink evasion to settings.json: expected deny, got allow")
			}
		} else {
			t.Skip("target path does not exist")
		}
	})

	t.Run("path with HOME env var", func(t *testing.T) {
		t.Parallel()
		argsJSON, _ := json.Marshal(map[string]string{"path": "$HOME/.nixis/policies/x.yaml"})
		req := nixis.CheckRequest{Tool: "Write", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("$HOME evasion: expected deny, got allow")
		}
	})

	t.Run("path with tilde", func(t *testing.T) {
		t.Parallel()
		argsJSON, _ := json.Marshal(map[string]string{"path": "~/.nixis/policies/x.yaml"})
		req := nixis.CheckRequest{Tool: "Write", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("tilde evasion: expected deny, got allow")
		}
	})

	t.Run("cron injection to kill nixis", func(t *testing.T) {
		t.Parallel()
		cmd := "echo '* * * * * kill $(pgrep nixis-daemon)' | crontab -"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := nixis.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("cron injection evasion: expected deny, got allow")
		}
	})

	t.Run("indirect git checkout in nixis dir", func(t *testing.T) {
		t.Parallel()
		cmd := "cd ~/.nixis/policies && git checkout -- ."
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := nixis.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("git checkout evasion in .nixis/: expected deny, got allow")
		}
	})

	t.Run("indirect git reset in nixis dir", func(t *testing.T) {
		t.Parallel()
		cmd := "git reset --hard HEAD -- ~/.nixis/policies/"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := nixis.CheckRequest{Tool: "Bash", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("git reset evasion targeting .nixis/: expected deny, got allow")
		}
	})

	t.Run("pipe to overwrite nixis file", func(t *testing.T) {
		t.Parallel()
		cmd := "cat /dev/null > ~/.nixis/config.yaml"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := nixis.CheckRequest{Tool: "Bash", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("cat redirect evasion: expected deny, got allow")
		}
	})

	t.Run("cp overwrite to nixis sock", func(t *testing.T) {
		t.Parallel()
		cmd := "cp /dev/null ~/.nixis/nixis.sock"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := nixis.CheckRequest{Tool: "Bash", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("cp to nixis.sock evasion: expected deny, got allow")
		}
	})

	t.Run("truncate nixis config", func(t *testing.T) {
		t.Parallel()
		cmd := "truncate -s 0 ~/.nixis/config.yaml"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := nixis.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("truncate evasion: expected deny, got allow")
		}
	})

	t.Run("com.nixis.daemon in launchctl remove", func(t *testing.T) {
		t.Parallel()
		cmd := "launchctl remove com.nixis.daemon"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := nixis.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("launchctl remove com.nixis.daemon: expected deny, got allow")
		}
	})
}

func TestSelfProtectGuard_NonShellToolsNotBlocked(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	req := nixis.CheckRequest{
		Tool: "Read",
		Args: json.RawMessage(`{"path":"/Users/test/.nixis/policies/builtin/foo.yaml"}`),
	}
	decision := g.Check(req)
	if decision != nil {
		t.Error("Read tool should not be blocked by self-protection")
	}
}

func TestSelfProtectGuard_EmptyArgs(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	req := nixis.CheckRequest{Tool: "Write", Args: nil}
	decision := g.Check(req)
	if decision != nil {
		t.Error("nil args should not trigger self-protection")
	}
}

func TestSelfProtectGuard_DecisionFields(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()
	home, _ := os.UserHomeDir()

	argsJSON, _ := json.Marshal(map[string]string{"path": filepath.Join(home, ".nixis/config.yaml")})
	req := nixis.CheckRequest{Tool: "Write", Args: argsJSON}
	decision := g.Check(req)
	if decision == nil {
		t.Fatal("expected deny decision")
	}

	if decision.Action != nixis.ActionDeny {
		t.Errorf("Action = %v, want ActionDeny", decision.Action)
	}
	if decision.PolicyID != "nixis-self-protection-guard" {
		t.Errorf("PolicyID = %q, want 'nixis-self-protection-guard'", decision.PolicyID)
	}
	if decision.Reason != selfProtectDenyReason {
		t.Errorf("Reason = %q, want %q", decision.Reason, selfProtectDenyReason)
	}
}

func BenchmarkSelfProtectGuard_Allow(b *testing.B) {
	g := NewSelfProtectGuard()
	argsJSON, _ := json.Marshal(map[string]string{"command": "ls -la /tmp"})
	req := nixis.CheckRequest{Tool: "Bash", Args: argsJSON}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Check(req)
	}
}

func BenchmarkSelfProtectGuard_Deny(b *testing.B) {
	g := NewSelfProtectGuard()
	argsJSON, _ := json.Marshal(map[string]string{"command": "rm -rf ~/.nixis/"})
	req := nixis.CheckRequest{Tool: "Bash", Args: argsJSON}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Check(req)
	}
}
