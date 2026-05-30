package cel_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/classify"
	"github.com/mayjain/aegis/internal/label"
	aegis "github.com/mayjain/aegis/pkg/aegis"
	policy_types "github.com/mayjain/aegis/pkg/policy/types"
)

// TestINV_014_PathCanonicalization verifies path.isWithinProject rejects
// symlink traversal escaping the project root (requires filepath.EvalSymlinks).
func TestINV_014_PathCanonicalization(t *testing.T) {
	env := mustNewEnv(t)

	root := t.TempDir()
	sub := filepath.Join(root, "src")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	inside := filepath.Join(sub, "file.go")
	if err := os.WriteFile(inside, []byte("package main"), 0o644); err != nil {
		t.Fatalf("write inside: %v", err)
	}

	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}

	// Symlink inside root points outside root.
	symlinkPath := filepath.Join(root, "escape")
	if err := os.Symlink(outside, symlinkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	escapePath := filepath.Join(symlinkPath, "secret.txt")

	template := policy_types.PolicyTemplate{
		ID:         "inv014-path",
		Name:       "inv014-path",
		Expression: `path.isWithinProject(args["target"], args["root"])`,
	}
	cache := mustCompile(t, env, []policy_types.PolicyTemplate{template})
	prog, ok := cache.Get("inv014-path")
	if !ok {
		t.Fatal("program not found in cache")
	}

	builder := cel.NewActivationBuilder()
	verdict := classify.VerdictEntry{RiskLevel: classify.RiskLow}

	// Path inside project: expression must evaluate to true.
	insideArgs := argsJSON(t, map[string]any{"target": inside, "root": root})
	insideReq := aegis.CheckRequest{Tool: "ReadFile", Args: insideArgs}
insideVal, err := builder.Evaluate(context.Background(), prog, insideReq, verdict, decodeArgs(t, insideArgs), label.LabeledRequest{}, nil, "")
	if err != nil {
		t.Fatalf("evaluate inside: %v", err)
	}
	if b, ok := insideVal.Value().(bool); !ok || !b {
		t.Error("INV-014: path inside project returned false, want true")
	}

	// Path via symlink escaping root: expression must evaluate to false.
	escapeRaw, _ := json.Marshal(map[string]any{"target": escapePath, "root": root})
	escapeReq := aegis.CheckRequest{Tool: "ReadFile", Args: escapeRaw}
escapeVal, err := builder.Evaluate(context.Background(), prog, escapeReq, verdict, decodeArgs(t, escapeRaw), label.LabeledRequest{}, nil, "")
	if err != nil {
		t.Fatalf("evaluate escape: %v", err)
	}
	if b, ok := escapeVal.Value().(bool); !ok || b {
		t.Error("INV-014 violated: symlink escape returned true, want false (EvalSymlinks must be used)")
	}
}
