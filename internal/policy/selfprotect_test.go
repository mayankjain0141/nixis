// SPDX-License-Identifier: MIT
package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mayjain/aegis/pkg/aegis"
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
		{name: "read aegis file allowed", tool: "Read", args: map[string]any{"path": "/Users/test/.aegis/policies/builtin/foo.yaml"}},
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
			req := aegis.CheckRequest{Tool: tt.tool, Args: argsJSON}
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
			name: "write to aegis policy builtin",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".aegis/policies/builtin/x.yaml")},
		},
		{
			name: "write to aegis hook binary",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".aegis/aegis-hook")},
		},
		{
			name: "write to settings.json",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".claude/settings.json")},
		},
		{
			name: "write to launchd plist",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, "Library/LaunchAgents/com.aegis.daemon.plist")},
		},
		{
			name: "write to systemd service",
			tool: "Write",
			args: map[string]any{"path": filepath.Join(home, ".config/systemd/user/aegis-daemon.service")},
		},
		{
			name: "delete aegis hook",
			tool: "Delete",
			args: map[string]any{"path": filepath.Join(home, ".aegis/aegis-hook")},
		},
		{
			name: "edit aegis policy",
			tool: "Edit",
			args: map[string]any{"path": filepath.Join(home, ".aegis/policies/builtin/self-protection.yaml")},
		},
		{
			name: "str_replace settings",
			tool: "StrReplace",
			args: map[string]any{"path": filepath.Join(home, ".claude/settings.json")},
		},
		{
			name: "multi_edit aegis config",
			tool: "MultiEdit",
			args: map[string]any{"target_file": filepath.Join(home, ".aegis/config.yaml")},
		},
		{
			name: "tilde path write",
			tool: "Write",
			args: map[string]any{"path": "~/.aegis/policies/custom/evil.yaml"},
		},
		{
			name: "HOME var path write",
			tool: "Write",
			args: map[string]any{"path": "$HOME/.aegis/policies/x.yaml"},
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
			req := aegis.CheckRequest{Tool: tt.tool, Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Fatal("expected deny, got allow (nil)")
			}
			if decision.Action != aegis.ActionDeny {
				t.Errorf("expected ActionDeny, got %v", decision.Action)
			}
			if decision.PolicyID != "aegis-self-protection-guard" {
				t.Errorf("expected PolicyID 'aegis-self-protection-guard', got %q", decision.PolicyID)
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
		{name: "kill pgrep aegis", command: "kill $(pgrep aegis)"},
		{name: "kill pgrep aegis-daemon", command: "kill $(pgrep aegis-daemon)"},
		{name: "pkill aegis-daemon", command: "pkill -9 aegis-daemon"},
		{name: "killall aegis-daemon", command: "killall aegis-daemon"},
		{name: "launchctl bootout", command: "launchctl bootout gui/501 com.aegis.daemon"},
		{name: "launchctl unload", command: "launchctl unload ~/Library/LaunchAgents/com.aegis.daemon.plist"},
		{name: "launchctl remove", command: "launchctl remove com.aegis.daemon"},
		{name: "systemctl stop", command: "systemctl --user stop aegis-daemon"},
		{name: "systemctl disable", command: "systemctl --user disable aegis-daemon"},
		{name: "systemctl mask", command: "systemctl --user mask aegis-daemon"},
		{name: "rm aegis dir", command: "rm -rf ~/.aegis/"},
		{name: "rm aegis hook", command: "rm ~/.aegis/aegis-hook"},
		{name: "mv aegis hook", command: "mv ~/.aegis/aegis-hook /tmp/"},
		{name: "chmod aegis hook", command: "chmod 000 ~/.aegis/aegis-hook"},
		{name: "chown aegis dir", command: "chown root:root ~/.aegis/"},
		{name: "aegis daemon stop", command: "aegis daemon stop"},
		{name: "aegis daemon restart", command: "aegis daemon restart"},
		{name: "aegis setup uninstall", command: "aegis setup --uninstall"},
		{name: "echo redirect to aegis", command: "echo 'exit 0' > ~/.aegis/aegis-hook"},
		{name: "tee to aegis", command: "echo '' | tee ~/.aegis/policies/builtin/allow-all.yaml"},
		{name: "sed on settings", command: "sed -i '' '/hooks/d' ~/.claude/settings.json"},
		{name: "crontab aegis kill", command: "echo '* * * * * kill $(pgrep aegis-daemon)' | crontab -"},
		{name: "crontab rm aegis", command: "crontab -l | echo '0 0 * * * rm -rf ~/.aegis' | crontab -"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			argsJSON, _ := json.Marshal(map[string]string{"command": tt.command})
			req := aegis.CheckRequest{Tool: "Bash", Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Fatalf("command %q: expected deny, got allow", tt.command)
			}
			if decision.Action != aegis.ActionDeny {
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
		targetPath := filepath.Join(home, ".aegis", "policies")

		if _, err := os.Stat(targetPath); err == nil {
			if err := os.Symlink(targetPath, symlinkPath); err != nil {
				t.Skipf("cannot create symlink: %v", err)
			}

			argsJSON, _ := json.Marshal(map[string]string{"path": filepath.Join(symlinkPath, "evil.yaml")})
			req := aegis.CheckRequest{Tool: "Write", Args: argsJSON}
			decision := g.Check(req)
			if decision == nil {
				t.Error("symlink evasion to .aegis/policies/: expected deny, got allow")
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
			req := aegis.CheckRequest{Tool: "Write", Args: argsJSON}
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
		argsJSON, _ := json.Marshal(map[string]string{"path": "$HOME/.aegis/policies/x.yaml"})
		req := aegis.CheckRequest{Tool: "Write", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("$HOME evasion: expected deny, got allow")
		}
	})

	t.Run("path with tilde", func(t *testing.T) {
		t.Parallel()
		argsJSON, _ := json.Marshal(map[string]string{"path": "~/.aegis/policies/x.yaml"})
		req := aegis.CheckRequest{Tool: "Write", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("tilde evasion: expected deny, got allow")
		}
	})

	t.Run("cron injection to kill aegis", func(t *testing.T) {
		t.Parallel()
		cmd := "echo '* * * * * kill $(pgrep aegis-daemon)' | crontab -"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := aegis.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("cron injection evasion: expected deny, got allow")
		}
	})

	t.Run("indirect git checkout in aegis dir", func(t *testing.T) {
		t.Parallel()
		cmd := "cd ~/.aegis/policies && git checkout -- ."
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := aegis.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("git checkout evasion in .aegis/: expected deny, got allow")
		}
	})

	t.Run("indirect git reset in aegis dir", func(t *testing.T) {
		t.Parallel()
		cmd := "git reset --hard HEAD -- ~/.aegis/policies/"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := aegis.CheckRequest{Tool: "Bash", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("git reset evasion targeting .aegis/: expected deny, got allow")
		}
	})

	t.Run("pipe to overwrite aegis file", func(t *testing.T) {
		t.Parallel()
		cmd := "cat /dev/null > ~/.aegis/config.yaml"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := aegis.CheckRequest{Tool: "Bash", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("cat redirect evasion: expected deny, got allow")
		}
	})

	t.Run("cp overwrite to aegis sock", func(t *testing.T) {
		t.Parallel()
		cmd := "cp /dev/null ~/.aegis/aegis.sock"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := aegis.CheckRequest{Tool: "Bash", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("cp to aegis.sock evasion: expected deny, got allow")
		}
	})

	t.Run("truncate aegis config", func(t *testing.T) {
		t.Parallel()
		cmd := "truncate -s 0 ~/.aegis/config.yaml"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := aegis.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("truncate evasion: expected deny, got allow")
		}
	})

	t.Run("com.aegis.daemon in launchctl remove", func(t *testing.T) {
		t.Parallel()
		cmd := "launchctl remove com.aegis.daemon"
		argsJSON, _ := json.Marshal(map[string]string{"command": cmd})
		req := aegis.CheckRequest{Tool: "Shell", Args: argsJSON}
		decision := g.Check(req)
		if decision == nil {
			t.Error("launchctl remove com.aegis.daemon: expected deny, got allow")
		}
	})
}

func TestSelfProtectGuard_NonShellToolsNotBlocked(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	req := aegis.CheckRequest{
		Tool: "Read",
		Args: json.RawMessage(`{"path":"/Users/test/.aegis/policies/builtin/foo.yaml"}`),
	}
	decision := g.Check(req)
	if decision != nil {
		t.Error("Read tool should not be blocked by self-protection")
	}
}

func TestSelfProtectGuard_EmptyArgs(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()

	req := aegis.CheckRequest{Tool: "Write", Args: nil}
	decision := g.Check(req)
	if decision != nil {
		t.Error("nil args should not trigger self-protection")
	}
}

func TestSelfProtectGuard_DecisionFields(t *testing.T) {
	t.Parallel()
	g := NewSelfProtectGuard()
	home, _ := os.UserHomeDir()

	argsJSON, _ := json.Marshal(map[string]string{"path": filepath.Join(home, ".aegis/config.yaml")})
	req := aegis.CheckRequest{Tool: "Write", Args: argsJSON}
	decision := g.Check(req)
	if decision == nil {
		t.Fatal("expected deny decision")
	}

	if decision.Action != aegis.ActionDeny {
		t.Errorf("Action = %v, want ActionDeny", decision.Action)
	}
	if decision.PolicyID != "aegis-self-protection-guard" {
		t.Errorf("PolicyID = %q, want 'aegis-self-protection-guard'", decision.PolicyID)
	}
	if decision.Reason != selfProtectDenyReason {
		t.Errorf("Reason = %q, want %q", decision.Reason, selfProtectDenyReason)
	}
}

func BenchmarkSelfProtectGuard_Allow(b *testing.B) {
	g := NewSelfProtectGuard()
	argsJSON, _ := json.Marshal(map[string]string{"command": "ls -la /tmp"})
	req := aegis.CheckRequest{Tool: "Bash", Args: argsJSON}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Check(req)
	}
}

func BenchmarkSelfProtectGuard_Deny(b *testing.B) {
	g := NewSelfProtectGuard()
	argsJSON, _ := json.Marshal(map[string]string{"command": "rm -rf ~/.aegis/"})
	req := aegis.CheckRequest{Tool: "Bash", Args: argsJSON}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g.Check(req)
	}
}
