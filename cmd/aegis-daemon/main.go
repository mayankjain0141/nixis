// aegis-daemon is the Aegis governance daemon binary.
//
// It listens on a Unix domain socket, evaluates incoming CheckRequests from the
// hook binary against the loaded policy set, and writes audit records to SQLite.
//
// Usage:
//
//	aegis-daemon [-socket PATH] [-policy-dir DIR] [-audit-db PATH]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/mayjain/aegis/internal/audit"
	"github.com/mayjain/aegis/internal/bundle"
	"github.com/mayjain/aegis/internal/cel"
	"github.com/mayjain/aegis/internal/daemon"
	"github.com/mayjain/aegis/internal/ifc"
	"github.com/mayjain/aegis/internal/policy"
	"github.com/mayjain/aegis/pkg/aegis"
)

func main() {
	var (
		socketPath  = flag.String("socket", "", "Unix socket path (default: $AEGIS_SOCKET_PATH or /tmp/aegis.sock)")
		policyDir   = flag.String("policy-dir", "policies/builtin", "Policy YAML directory")
		auditDB     = flag.String("audit-db", "~/.aegis/audit.db", "Audit SQLite database path")
		failOpenLog = flag.String("failopen-log", "", "Fail-open log path (default: $AEGIS_FAILOPEN_LOG or ~/.aegis/failopen.log)")
	)
	flag.Parse()

	cfg := daemon.Config{
		SocketPath:  *socketPath,
		PolicyDir:   *policyDir,
		AuditDBPath: expandHome(*auditDB),
		FailOpenLog: *failOpenLog,
	}

	auditWriter, err := audit.NewWriter(cfg.AuditDBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-daemon: failed to open audit database %q: %v\n", cfg.AuditDBPath, err)
		os.Exit(1)
	}

	sessions := &ifc.SessionLabels{}
	celEnv, err := cel.NewCELEnvironment()
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-daemon: failed to create CEL environment: %v\n", err)
		os.Exit(1)
	}

	engine := policy.NewPolicyEngine(
		sessions,
		celEnv,
		policy.WithAuditWriter(auditWriter),
	)

	ctx, cancel := context.WithCancel(context.Background())

	templates, bindings, err := bundle.ParsePolicyDir(cfg.PolicyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aegis-daemon: failed to parse policies from %q: %v\n", cfg.PolicyDir, err)
		fmt.Fprintf(os.Stderr, "aegis-daemon: starting with no policies (all requests will be denied)\n")
	} else {
		compiled := &aegis.CompiledBundle{
			Version:   1,
			Templates: templates,
			Bindings:  bindings,
		}
		if err := engine.Reload(ctx, compiled); err != nil {
			fmt.Fprintf(os.Stderr, "aegis-daemon: failed to load initial policies: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "aegis-daemon: loaded %d policies from %s\n", len(templates), cfg.PolicyDir)
		}
	}
	auditDone := make(chan struct{})
	go func() {
		defer close(auditDone)
		auditWriter.Start(ctx)
	}()

	d := daemon.New(cfg, engine, auditWriter)
	d.SetAuditContext(cancel, auditDone)

	if err := d.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "aegis-daemon: %v\n", err)
		os.Exit(1)
	}
}

// expandHome replaces a leading ~ with the user's home directory.
func expandHome(path string) string {
	if len(path) == 0 || path[0] != '~' {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return home + path[1:]
}
