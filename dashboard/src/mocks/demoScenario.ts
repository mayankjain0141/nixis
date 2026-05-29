/**
 * Scripted demo scenario — 32 events over ~35 seconds.
 *
 * Covers every engine component:
 *   bundle.activated        → policy sidebar, MetricsBar bundle version
 *   policy.evaluated(allow) → event stream, governance DAG, latency breakdown
 *   label.escalated         → IFC lattice sessions move up, label state changes
 *   policy.denied           → Inspector "Why Denied", DENY color in stream
 *   secret.detected         → Threat timeline, tainted_by_secret state
 *   policy.evaluated(require_approval) → HITL verdict in stream
 *   delegation.created      → Delegation tree, Inspector delegation chain
 *   audit.checkpoint        → Audit hash chain
 *   mcp.tool_drift          → Threat timeline orange dot
 *   bundle.activated(v2)    → Policy reload
 *   delegation.expired      → Tree updates
 */

import { getAllImportedPolicies as getAllImportedPoliciesSync } from './allPolicies';

export interface DemoStep {
  delayMs: number;   // ms to wait after the previous event before emitting this one
  json: string;      // CloudEvent JSON string
}

// ── Security label constants ──────────────────────────────────────────────────
const L_UNCLASSIFIED  = { confidentiality: 0,     integrity: 0,     categories: 0 };
const L_INTERNAL      = { confidentiality: 8192,  integrity: 8192,  categories: 0 };
const L_CONFIDENTIAL  = { confidentiality: 32768, integrity: 16384, categories: 2 };  // finance
const L_RESTRICTED    = { confidentiality: 49152, integrity: 32768, categories: 7 };  // credentials|finance|pii

// ── Session IDs ───────────────────────────────────────────────────────────────
const SESS_MAIN      = 'sess_7f3a91bc'; // primary agent — starts Unclassified
const SESS_DELEGATE  = 'sess_2e8c04d1'; // delegated sub-agent — ceiling: Internal
const SESS_OPERATOR  = 'sess_b5f60a2e'; // operator review session — Restricted

// ── Policy definitions ────────────────────────────────────────────────────────
const POLICIES = [
  { id: 'aegis/no-force-push',           cel: 'tool == "Bash" && request.args.command.matches(".*push.*--force.*|.*--force.*push.*")' },
  { id: 'aegis/no-rm-rf',               cel: 'tool == "Bash" && request.args.command.matches(".*rm\\s+-rf.*")' },
  { id: 'aegis/protect-etc',            cel: 'tool in ["Write","Edit","FileDelete"] && request.args.path.startsWith("/etc/")' },
  { id: 'aegis/require-approval-prod',  cel: 'tool == "DatabaseQuery" && request.args.db.startsWith("prod-")' },
  { id: 'aegis/audit-secret-reads',     cel: 'tool == "Read" && request.args.path.matches(".*(secret|api.key|passwd|shadow).*")' },
  { id: 'aegis/no-secret-transmission', cel: '!response.contains_secret || verdict == "deny"' },
];

// ── Imported policy sample — real policies from the imported catalog ──────────
// These appear in the bundle alongside the 6 core policies so the sidebar shows
// what the daemon would actually load from disk (696 policies available).
const IMPORTED_POLICIES = [
  { id: 'gatekeeper/block-load-balancer',     cel: 'tool == "Bash" && request.args.command.matches("kubectl.*")' },
  { id: 'gatekeeper/verify-deprecated-api',   cel: 'tool == "Bash" && request.args.command.matches("kubectl.*")' },
  { id: 'gatekeeper/container-limits',        cel: 'tool == "Bash" && request.args.command.matches("kubectl.*(create|apply).*")' },
  { id: 'falco/ssh-keys-authorized',          cel: 'tool == "Bash" && request.args.command.matches("(?i)\\\\b(ssh-keygen|ssh-add|ssh-keyscan)\\\\b")' },
  { id: 'falco/backdoored-library-cve-2024',  cel: 'tool.matches("Read|Write|Edit") && request.args.path.contains("liblzma.so.5.6.0")' },
  { id: 'kyverno/no-privileged-containers',   cel: 'tool == "Bash" && request.args.command.matches(".*privileged.*")' },
  { id: 'agentwall/no-web-scraping',          cel: 'tool == "WebFetch" && request.args.url.matches(".*\\\\.(onion|i2p).*")' },
  { id: 'agentwall/rate-limit-llm-calls',     cel: 'tool == "WebFetch" && request.args.url.matches(".*(openai|anthropic|huggingface)\\\\..*")' },
  { id: 'sigma/masquerading-execution',       cel: 'tool == "Bash" && request.args.command.matches(".*(rundll32|regsvr32|mshta).*")' },
  { id: 'catalog/block-kubectl-delete-node',  cel: 'tool == "Bash" && request.args.command.matches("kubectl delete node.*")' },
];

// ── Direct policy export — bypasses ingestion pipeline Zod validation ────────
// Returns ALL imported policies (700+) plus the 6 core aegis policies.
// Called from App.tsx when demo mode starts so CEL expressions are immediately visible.
export function getDemoPolicies(bundleVersion: number = 1): import('../stores/policy-store').PolicySummary[] {
  const imported = getAllImportedPoliciesSync(bundleVersion);

  // Prepend the 6 core demo policies (they may also exist in imported but these have richer demo CEL)
  const core: import('../stores/policy-store').PolicySummary[] = POLICIES.map(p => ({
    id: p.id,
    name: p.id.replace(/^aegis\//, ''),
    layer: 'cel' as const,
    enabled: true,
    bundleVersion,
    celExpression: p.cel,
    description: 'Core Aegis policy',
  }));

  // Merge: core policies first (by id), then imported (deduped)
  const coreIds = new Set(core.map(p => p.id));
  return [...core, ...imported.filter(p => !coreIds.has(p.id))];
}

// ── Helper builders ───────────────────────────────────────────────────────────
let _seq = 0;
function seq(): number { return ++_seq; }

function ce(type: string, data: Record<string, unknown>, overrideSeq?: number): string {
  const s = overrideSeq ?? seq();
  return JSON.stringify({
    specversion: '1.0',
    type,
    source: 'aegis-demo/local',
    id: `demo-${s}`,
    time: new Date().toISOString(),
    datacontenttype: 'application/json',
    aegissequence: s,
    data,
  });
}

function policyEval(opts: {
  tool: string;
  sessionId: string;
  action: 'allow' | 'deny' | 'require_approval' | 'audit';
  reason?: string;
  policyId?: string;
  cel?: string;
  layer?: string;
  label?: typeof L_UNCLASSIFIED;
  labelState?: string;
  latencyNs?: number;
  requestArgs?: string;   // the actual command / path / query that triggered evaluation
}): string {
  const type = (opts.action === 'deny' || opts.action === 'require_approval')
    ? 'policy.denied' : 'policy.evaluated';
  return ce(type, {
    tool: opts.tool,
    session_id: opts.sessionId,
    request_args: opts.requestArgs,
    decision: {
      action: opts.action,
      reason: opts.reason ?? '',
      policy_id: opts.policyId ?? 'aegis/default-allow',
      enforcing_layer: opts.layer ?? 'cel',
      labels: opts.label ?? L_UNCLASSIFIED,
      cel_expression: opts.cel ?? '',
    },
    label_state: opts.labelState ?? 'fresh',
    latency_ns: opts.latencyNs ?? Math.floor(80_000 + Math.random() * 200_000),
  });
}

// ── The scenario ──────────────────────────────────────────────────────────────

export function buildDemoScenario(): DemoStep[] {
  _seq = 0; // reset for determinism

  return [
    // ── 0.0s: Bundle v1 loads — 6 policies appear in sidebar ──────────────────
    {
      delayMs: 0,
      json: ce('bundle.activated', {
        version: 1,
        policy_count: 16,
        signatureVerified: true,
        hash: 'sha256:a3f8c1e5b2d7049f6a1e3c8b5d2f7049a3f8c1e5b2d7049f6a1e3c8b5d2f704',
        activated_at: Date.now(),
        policies: [
          ...POLICIES.map(p => ({ id: p.id, enabled: true, layer: 'cel', cel_expression: p.cel })),
          ...IMPORTED_POLICIES.map(p => ({ id: p.id, enabled: true, layer: 'cel', cel_expression: p.cel })),
        ],
      }),
    },

    // ── 0.8s: Agent starts working — Read, allow ──────────────────────────────
    {
      delayMs: 800,
      json: policyEval({
        tool: 'Read',
        sessionId: SESS_MAIN,
        action: 'allow',
        policyId: 'aegis/default-allow',
        cel: 'tool == "Read"',
        label: L_UNCLASSIFIED,
        latencyNs: 92_000,
        requestArgs: '/home/user/project/README.md',
      }),
    },

    // ── 1.8s: Bash ls — allow ─────────────────────────────────────────────────
    {
      delayMs: 1000,
      json: policyEval({
        tool: 'Bash',
        sessionId: SESS_MAIN,
        action: 'allow',
        policyId: 'aegis/default-allow',
        cel: '!(tool == "Bash" && request.args.command.matches(".*rm\\s+-rf.*|.*--force.*"))',
        label: L_UNCLASSIFIED,
        latencyNs: 115_000,
        requestArgs: 'ls -la /home/user/project/',
      }),
    },

    // ── 2.8s: Write — allow ───────────────────────────────────────────────────
    {
      delayMs: 1000,
      json: policyEval({
        tool: 'Write',
        sessionId: SESS_MAIN,
        action: 'allow',
        policyId: 'aegis/protect-etc',
        cel: 'tool in ["Write","Edit","FileDelete"] && request.args.path.startsWith("/etc/")',
        label: L_UNCLASSIFIED,
        latencyNs: 178_000,
      }),
    },

    // ── 3.6s: WebSearch — allow ───────────────────────────────────────────────
    {
      delayMs: 800,
      json: policyEval({
        tool: 'WebSearch',
        sessionId: SESS_MAIN,
        action: 'allow',
        label: L_UNCLASSIFIED,
        latencyNs: 73_000,
      }),
    },

    // ── 5.2s: Read /var/secrets/api.key — slow cold-cache miss, audit verdict ─
    {
      delayMs: 1600,
      json: policyEval({
        tool: 'Read',
        sessionId: SESS_MAIN,
        action: 'audit',
        reason: 'Sensitive path read — audit trail required',
        policyId: 'aegis/audit-secret-reads',
        cel: 'tool == "Read" && request.args.path.matches(".*(secret|api.key|passwd|shadow).*")',
        label: L_UNCLASSIFIED,
        latencyNs: 3_200_000, // 3.2ms — cold CEL program compile
        requestArgs: '/var/secrets/api.key',
      }),
    },

    // ── 6.4s: Label escalates Unclassified → Confidential (finance) ──────────
    {
      delayMs: 1200,
      json: ce('label.escalated', {
        session_id: SESS_MAIN,
        label: L_CONFIDENTIAL,
        label_state: 'escalated',
        reason: 'Read of classified resource elevated session ceiling',
        previous_label: L_UNCLASSIFIED,
      }),
    },

    // ── 7.6s: DatabaseQuery prod-users — require_approval ────────────────────
    {
      delayMs: 1200,
      json: policyEval({
        tool: 'DatabaseQuery',
        sessionId: SESS_MAIN,
        action: 'require_approval',
        reason: 'Production database access requires human approval',
        policyId: 'aegis/require-approval-prod',
        cel: 'tool == "DatabaseQuery" && request.args.db.startsWith("prod-")',
        label: L_CONFIDENTIAL,
        labelState: 'escalated',
        latencyNs: 245_000,
        requestArgs: 'SELECT * FROM prod-users WHERE email LIKE "%@company.com"',
      }),
    },

    // ── 9.0s: git push --force — DENY ────────────────────────────────────────
    {
      delayMs: 1400,
      json: policyEval({
        tool: 'Bash',
        sessionId: SESS_MAIN,
        action: 'deny',
        reason: 'Force push to protected branch is prohibited by policy',
        policyId: 'aegis/no-force-push',
        cel: 'tool == "Bash" && request.args.command.matches(".*push.*--force.*|.*--force.*push.*")',
        label: L_CONFIDENTIAL,
        labelState: 'escalated',
        latencyNs: 189_000,
        requestArgs: 'git push --force origin main',
      }),
    },

    // ── 10.2s: Read — allow (normal operation continues) ─────────────────────
    {
      delayMs: 1200,
      json: policyEval({
        tool: 'Read',
        sessionId: SESS_MAIN,
        action: 'allow',
        label: L_CONFIDENTIAL,
        labelState: 'escalated',
        latencyNs: 88_000,
      }),
    },

    // ── 11.6s: Secret detected — AWS key in WebFetch response ─────────────────
    {
      delayMs: 1400,
      json: ce('secret.detected', {
        session_id: SESS_MAIN,
        tool: 'WebFetch',
        secret_type: 'AWS_SECRET_ACCESS_KEY',
        entropy: 4.8,
        redacted: true,
        label: L_CONFIDENTIAL,
      }),
    },

    // ── 12.0s: Session taints to Restricted ───────────────────────────────────
    {
      delayMs: 400,
      json: ce('label.escalated', {
        session_id: SESS_MAIN,
        label: L_RESTRICTED,
        label_state: 'tainted_by_secret',
        reason: 'Secret detected in response — session tainted, ceiling elevated to Restricted',
        previous_label: L_CONFIDENTIAL,
      }),
    },

    // ── 13.0s: Write /etc/passwd — DENY (protect-etc) ────────────────────────
    {
      delayMs: 1000,
      json: policyEval({
        tool: 'Write',
        sessionId: SESS_MAIN,
        action: 'deny',
        reason: 'Writes to /etc/ are prohibited on tainted sessions',
        policyId: 'aegis/protect-etc',
        cel: 'tool in ["Write","Edit","FileDelete"] && request.args.path.startsWith("/etc/")',
        label: L_RESTRICTED,
        labelState: 'tainted_by_secret',
        latencyNs: 201_000,
        requestArgs: '/etc/passwd',
      }),
    },

    // ── 14.2s: Delegation created — main delegates to sub-agent at Internal ───
    {
      delayMs: 1200,
      json: ce('delegation.created', {
        session_id: SESS_DELEGATE,
        delegator_id: SESS_MAIN,
        delegatee_id: SESS_DELEGATE,
        granted_label: L_INTERNAL,
        ceiling_label: L_INTERNAL,
        capabilities: ['Read', 'Write', 'Bash', 'WebSearch'],
        expires_at: Date.now() + 30_000,
        reason: 'Sub-agent granted restricted capability for file processing task',
      }),
    },

    // ── 15.2s: Delegate: Bash echo — allow ───────────────────────────────────
    {
      delayMs: 1000,
      json: policyEval({
        tool: 'Bash',
        sessionId: SESS_DELEGATE,
        action: 'allow',
        label: L_INTERNAL,
        layer: 'delegation',
        latencyNs: 62_000,
      }),
    },

    // ── 16.0s: Delegate: Read safe file — allow ───────────────────────────────
    {
      delayMs: 800,
      json: policyEval({
        tool: 'Read',
        sessionId: SESS_DELEGATE,
        action: 'allow',
        label: L_INTERNAL,
        layer: 'delegation',
        latencyNs: 54_000,
      }),
    },

    // ── 16.8s: Operator session: Bash npm install at Restricted ───────────────
    {
      delayMs: 800,
      json: policyEval({
        tool: 'Bash',
        sessionId: SESS_OPERATOR,
        action: 'allow',
        label: L_RESTRICTED,
        labelState: 'fresh',
        latencyNs: 143_000,
      }),
    },

    // ── 17.6s: Delegate: WebSearch — allow ────────────────────────────────────
    {
      delayMs: 800,
      json: policyEval({
        tool: 'WebSearch',
        sessionId: SESS_DELEGATE,
        action: 'allow',
        label: L_INTERNAL,
        layer: 'delegation',
        latencyNs: 58_000,
      }),
    },

    // ── 18.8s: Audit checkpoint ───────────────────────────────────────────────
    {
      delayMs: 1200,
      json: ce('audit.checkpoint', {
        sequence: 18,
        hash: 'sha256:4a7f9b2c1e8d3f6a0b5c9d2e7f4a1b8c3d6e9f2a5b8c1d4e7f0a3b6c9d2e5f8a',
        prev_hash: 'sha256:1b4e7a0d3f6c9b2e5a8d1f4c7a0e3b6d9f2c5a8e1b4d7f0c3e6a9b2d5f8c1e4',
        events_since_prev: 18,
        merkle_root: 'sha256:9f2c5a8e1b4d7f0c3e6a9b2d5f8c1e4a7b0d3f6c9e2a5b8c1d4f7a0e3b6c9d',
      }),
    },

    // ── 20.0s: MCP tool drift detected ───────────────────────────────────────
    {
      delayMs: 1200,
      json: ce('mcp.tool_drift', {
        tool_name: 'WebSearch',
        session_id: SESS_MAIN,
        previous_hash: 'sha256:abc123',
        current_hash: 'sha256:def456',
        severity: 'warning',
        description: 'WebSearch tool definition changed — schema hash mismatch',
      }),
    },

    // ── 20.8s: Operator: Read log file — audit ────────────────────────────────
    {
      delayMs: 800,
      json: policyEval({
        tool: 'Read',
        sessionId: SESS_OPERATOR,
        action: 'audit',
        reason: 'Access to audit logs at Restricted level recorded',
        policyId: 'aegis/audit-secret-reads',
        cel: 'tool == "Read" && request.args.path.matches(".*(secret|api.key|passwd|shadow).*")',
        label: L_RESTRICTED,
        latencyNs: 2_800_000,
      }),
    },

    // ── 21.6s: kubectl apply — DENY via gatekeeper/block-load-balancer ──────────
    {
      delayMs: 800,
      json: policyEval({
        tool: 'Bash',
        sessionId: SESS_OPERATOR,
        action: 'deny',
        reason: 'OPA Gatekeeper: kubectl operations are audited — LoadBalancer type blocked',
        policyId: 'gatekeeper/block-load-balancer',
        cel: 'tool == "Bash" && request.args.command.matches("kubectl.*")',
        label: L_RESTRICTED,
        latencyNs: 312_000,
        requestArgs: 'kubectl apply -f loadbalancer-service.yaml',
      }),
    },

    // ── 22.0s: Delegation expired ─────────────────────────────────────────────
    {
      delayMs: 1200,
      json: ce('delegation.expired', {
        session_id: SESS_DELEGATE,
        delegator_id: SESS_MAIN,
        reason: 'Delegation TTL elapsed',
        expired_at: Date.now(),
      }),
    },

    // ── 23.2s: rm -rf — DENY ─────────────────────────────────────────────────
    {
      delayMs: 1200,
      json: policyEval({
        tool: 'Bash',
        sessionId: SESS_MAIN,
        action: 'deny',
        reason: 'Recursive force-delete blocked by policy',
        policyId: 'aegis/no-rm-rf',
        cel: 'tool == "Bash" && request.args.command.matches(".*rm\\s+-rf.*")',
        label: L_RESTRICTED,
        labelState: 'tainted_by_secret',
        latencyNs: 166_000,
        requestArgs: 'rm -rf /tmp/critical-data/',
      }),
    },

    // ── 24.4s: Operator session escalates to Restricted (label.escalated) ─────
    {
      delayMs: 1200,
      json: ce('label.escalated', {
        session_id: SESS_OPERATOR,
        label: L_RESTRICTED,
        label_state: 'escalated',
        reason: 'Operator reviewed classified output — session elevated',
        previous_label: L_RESTRICTED,
      }),
    },

    // ── 25.4s: Write /tmp/report.md — allow ──────────────────────────────────
    {
      delayMs: 1000,
      json: policyEval({
        tool: 'Write',
        sessionId: SESS_MAIN,
        action: 'allow',
        label: L_RESTRICTED,
        labelState: 'tainted_by_secret',
        latencyNs: 97_000,
      }),
    },

    // ── 26.8s: Bundle v2 loads — 7 policies (one new: rate-limit) ─────────────
    {
      delayMs: 1400,
      json: ce('bundle.activated', {
        version: 2,
        hash: 'sha256:b8f3d2a1e6c9047f5b2e4a7d0c3f8a1e6b9d2c5f8a3e6b9d2c5a8e1b4d7f0c3',
        signatureVerified: true,
        policy_count: 7,
        activated_at: Date.now(),
        policies: [
          ...POLICIES.map(p => ({ id: p.id, enabled: true, layer: 'cel', cel_expression: p.cel })),
          { id: 'aegis/rate-limit-writes', enabled: true, layer: 'cel', cel_expression: 'write_rate_per_minute < 60' },
        ],
      }),
    },

    // ── 28.0s: Operator: Read /etc/config — allow (new bundle active) ─────────
    {
      delayMs: 1200,
      json: policyEval({
        tool: 'Read',
        sessionId: SESS_OPERATOR,
        action: 'allow',
        policyId: 'aegis/audit-secret-reads',
        label: L_RESTRICTED,
        labelState: 'escalated',
        latencyNs: 84_000,
      }),
    },

    // ── 29.2s: Edit — allow (rate-limit-writes now active) ────────────────────
    {
      delayMs: 1200,
      json: policyEval({
        tool: 'Edit',
        sessionId: SESS_MAIN,
        action: 'allow',
        policyId: 'aegis/rate-limit-writes',
        cel: 'write_rate_per_minute < 60',
        label: L_RESTRICTED,
        labelState: 'tainted_by_secret',
        latencyNs: 121_000,
      }),
    },

    // ── 30.4s: Heartbeat ─────────────────────────────────────────────────────
    {
      delayMs: 1200,
      json: ce('stream.heartbeat', {
        server_time: Date.now() * 1_000_000,
        sequence: _seq + 1,
      }),
    },
  ];
}

/**
 * Play back the demo scenario, calling onEvent for each step.
 * Returns a cancel function.
 */
export function runDemoScenario(
  onEvent: (json: string, seq: number) => void,
  onComplete?: () => void,
): () => void {
  const steps = buildDemoScenario();
  let cancelled = false;
  let localSeq = 0;
  let timeoutId: ReturnType<typeof setTimeout>;

  function scheduleNext(index: number, accumulatedDelay: number) {
    if (cancelled || index >= steps.length) {
      if (!cancelled) onComplete?.();
      return;
    }
    const step = steps[index];
    const delay = accumulatedDelay + step.delayMs;
    timeoutId = setTimeout(() => {
      if (cancelled) return;
      onEvent(step.json, ++localSeq);
      scheduleNext(index + 1, 0);
    }, delay);
  }

  scheduleNext(0, 0);

  return () => {
    cancelled = true;
    clearTimeout(timeoutId);
  };
}
