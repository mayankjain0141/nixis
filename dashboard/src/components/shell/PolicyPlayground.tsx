import { useState } from 'react';
import { usePolicyStore } from '../../stores/policy-store';

const TOOLS = ['Bash', 'Read', 'Write', 'Edit', 'WebFetch', 'WebSearch', 'DatabaseQuery', 'GitCommit', 'GitPush', 'FileDelete'];

function simulateEval(
  tool: string,
  args: string,
  _policyId: string,
  cel: string,
): 'allow' | 'deny' | 'require_approval' | 'audit' {
  const combined = `${tool} ${args}`.toLowerCase();
  const celLower = cel.toLowerCase();

  if (celLower.includes('force') && (combined.includes('--force') || combined.includes('force push'))) return 'deny';
  if (celLower.includes('rm') && combined.includes('rm') && (combined.includes('-rf') || combined.includes('-fr'))) return 'deny';
  if (celLower.includes('/etc/') && (tool === 'Write' || tool === 'Edit' || tool === 'FileDelete') && args.includes('/etc/')) return 'deny';
  if (celLower.includes('prod') && tool === 'DatabaseQuery' && args.toLowerCase().includes('prod')) return 'require_approval';
  if (celLower.includes('secret') && tool === 'Read' && /secret|api\.key|passwd|shadow/.test(args)) return 'audit';
  // no-secret-transmission: deny if args explicitly contain a known secret pattern (simulated)
  if (celLower.includes('contains_secret') && /AWS_SECRET|api_key|password\s*=|token\s*=/i.test(args)) return 'deny';
  // gatekeeper/imported: kubectl command matching
  if (celLower.includes('kubectl') && tool === 'Bash' && args.toLowerCase().includes('kubectl')) {
    if (celLower.includes('nodeport') && args.toLowerCase().includes('nodeport')) return 'deny';
    if (celLower.includes('create|apply') && /kubectl.*(create|apply)/i.test(args)) return 'deny';
    return 'deny'; // most kubectl-matching policies are DENY
  }
  // falco/ssh: SSH key operations
  if (celLower.includes('ssh') && tool === 'Bash' && /ssh-keygen|ssh-add|ssh-keyscan/i.test(args)) return 'deny';
  // falco/xz: backdoored library
  if (celLower.includes('liblzma') && args.includes('liblzma.so.5.6.0')) return 'deny';

  return 'allow';
}

export function PolicyPlayground() {
  const policies = usePolicyStore((s) => s.policies);
  const [tool, setTool] = useState('Bash');
  const [args, setArgs] = useState('');
  const [result, setResult] = useState<null | {
    verdict: string;
    policyName: string;
    cel: string;
    explanation: string;
  }>(null);

  function handleEvaluate() {
    if (!args.trim()) return;

    let finalVerdict: string = 'allow';
    let matchedPolicy = { id: 'aegis/default-allow', name: 'default-allow', cel: 'true' };

    for (const policy of policies) {
      const cel = policy.celExpression ?? '';
      const verdict = simulateEval(tool, args, policy.id, cel);
      if (verdict !== 'allow') {
        finalVerdict = verdict;
        matchedPolicy = { id: policy.id, name: policy.name, cel };
        break;
      }
    }

    const explanations: Record<string, string> = {
      deny: 'This operation is blocked by policy. The CEL expression evaluated to true, triggering a DENY verdict.',
      require_approval: 'This operation requires human approval before proceeding. A HITL gate is triggered.',
      audit: 'This operation is allowed but will be recorded in the audit trail for review.',
      allow: 'No policy matched — the default-allow rule applies. This operation would proceed.',
    };

    setResult({
      verdict: finalVerdict,
      policyName: matchedPolicy.name,
      cel: matchedPolicy.cel,
      explanation: explanations[finalVerdict],
    });
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

      <button
        onClick={handleEvaluate}
        style={{
          width: '100%', padding: '8px', borderRadius: 6, cursor: 'pointer',
          background: args.trim() ? 'var(--info-blue)' : 'var(--bg-overlay)',
          color: args.trim() ? '#fff' : 'var(--text-muted)',
          border: 'none', fontWeight: 600, fontSize: 13,
        }}
      >
        Evaluate against {policies.length > 0 ? `${policies.length} policies` : 'policies'}
      </button>

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

          <div style={{ padding: '10px 14px', fontSize: 12 }}>
            <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>
              Matched policy:{' '}
              <span style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>
                {result.policyName}
              </span>
            </div>
            {result.cel && result.cel !== 'true' && (
              <pre style={{
                background: 'var(--bg-base)', border: '1px solid var(--border)',
                borderRadius: 4, padding: '6px 8px', margin: '6px 0 0',
                fontFamily: 'monospace', fontSize: 11, color: '#79c0ff',
                whiteSpace: 'pre-wrap' as const, wordBreak: 'break-all' as const,
              }}>{result.cel}</pre>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
