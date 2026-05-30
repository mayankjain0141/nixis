import { useState } from 'react';
import { usePolicyStore } from '../../stores/policy-store';
import { getDaemonApiBase } from '../../lib/api';

const TOOLS = ['Bash', 'Read', 'Write', 'Edit', 'WebFetch', 'WebSearch', 'DatabaseQuery', 'GitCommit', 'GitPush', 'FileDelete'];

type SimulateResult = { verdict: string; explanation: string; latencyNs: number } | null;

export function PolicyPlayground() {
  const policies = usePolicyStore((s) => s.policies);
  const [tool, setTool] = useState('Bash');
  const [args, setArgs] = useState('');
  const [celExpression, setCelExpression] = useState('');
  const [result, setResult] = useState<SimulateResult>(null);
  const [daemonError, setDaemonError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleEvaluate() {
    if (!args.trim()) return;
    setDaemonError(null);
    setResult(null);
    setLoading(true);
    try {
      const expression = celExpression.trim() || (policies[0]?.celExpression ?? '');
      const resp = await fetch(`${getDaemonApiBase()}/simulate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool,
          args: JSON.stringify(args),
          session_id: crypto.randomUUID(),
          timestamp: Date.now(),
          cel_expression: expression,
        }),
      });
      if (!resp.ok) throw new Error(`daemon: HTTP ${resp.status}`);
      setResult(await resp.json() as SimulateResult);
    } catch (err) {
      setDaemonError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  const verdictColors: Record<string, string> = {
    deny: 'var(--deny)',
    allow: 'var(--allow)',
    require_approval: 'var(--escalate)',
    audit: 'var(--audit-purple)',
  };

  return (
    <div style={{ maxWidth: 520, padding: 4 }}>
      <div style={{ marginBottom: 16 }}>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4, textTransform: 'uppercase' as const, letterSpacing: '0.06em' }}>
          Policy Evaluation Playground
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          Simulate a tool call against active policies without executing it.
        </div>
      </div>

      <label style={{ display: 'block', marginBottom: 10 }}>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>Tool</div>
        <select
          value={tool}
          onChange={e => setTool(e.target.value)}
          style={{
            width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 4, padding: '6px 8px', color: 'var(--text-primary)',
            fontSize: 13, fontFamily: 'monospace',
          }}
        >
          {TOOLS.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
      </label>

      <label style={{ display: 'block', marginBottom: 12 }}>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>
          Command / Arguments
        </div>
        <textarea
          value={args}
          onChange={e => setArgs(e.target.value)}
          placeholder="e.g. git push --force origin main"
          rows={3}
          style={{
            width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 4, padding: '6px 8px', color: 'var(--text-primary)',
            fontSize: 13, fontFamily: 'monospace', resize: 'vertical',
            outline: 'none', boxSizing: 'border-box',
          }}
          onKeyDown={e => { if (e.key === 'Enter' && e.metaKey) handleEvaluate(); }}
        />
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>Cmd+Enter to evaluate</div>
      </label>

      <label style={{ display: 'block', marginBottom: 12 }}>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>
          CEL Expression (optional — defaults to first active policy)
        </div>
        <input
          value={celExpression}
          onChange={e => setCelExpression(e.target.value)}
          placeholder={policies[0]?.celExpression ?? 'tool == "Bash"'}
          style={{
            width: '100%', background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 4, padding: '6px 8px', color: 'var(--text-primary)',
            fontSize: 13, fontFamily: 'monospace', outline: 'none', boxSizing: 'border-box',
          }}
        />
      </label>

      <button
        onClick={handleEvaluate}
        disabled={loading || !args.trim()}
        style={{
          width: '100%', padding: '8px', borderRadius: 6,
          cursor: loading || !args.trim() ? 'not-allowed' : 'pointer',
          background: args.trim() && !loading ? 'var(--info-blue)' : 'var(--bg-overlay)',
          color: args.trim() && !loading ? '#fff' : 'var(--text-muted)',
          border: 'none', fontWeight: 600, fontSize: 13,
        }}
      >
        {loading ? 'Evaluating…' : `Evaluate against ${policies.length > 0 ? `${policies.length} policies` : 'policies'}`}
      </button>

      {daemonError && (
        <div style={{ color: '#d29922', fontSize: 12, padding: '8px 0' }}>
          Daemon required — {daemonError}
        </div>
      )}

      {result && (
        <div style={{
          marginTop: 16, borderRadius: 6, overflow: 'hidden',
          border: `1px solid ${verdictColors[result.verdict] ?? 'var(--border)'}`,
          background: 'var(--bg-surface)',
        }}>
          <div style={{
            padding: '12px 14px', borderBottom: '1px solid var(--border)',
            background: result.verdict === 'deny' ? 'rgba(207,34,46,0.08)' : 'transparent',
          }}>
            <span
              data-verdict={result.verdict}
              style={{
                fontSize: 22, fontWeight: 800, letterSpacing: '-0.01em',
                color: verdictColors[result.verdict] ?? 'var(--text-primary)',
              }}
            >
              {result.verdict.toUpperCase().replace(/_/g, ' ')}
            </span>
          </div>

          <div style={{
            padding: '10px 14px', fontSize: 12, color: 'var(--text-secondary)',
            lineHeight: 1.6, borderBottom: '1px solid var(--border)',
          }}>
            {result.explanation}
          </div>

          {result.latencyNs > 0 && (
            <div style={{ padding: '6px 14px', fontSize: 11, color: 'var(--text-muted)' }}>
              Latency: {(result.latencyNs / 1_000_000).toFixed(2)} ms
            </div>
          )}
        </div>
      )}
    </div>
  );
}
