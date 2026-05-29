/**
 * Loads all 700+ imported policy YAML files at build time via Vite's import.meta.glob.
 * Parses CEL expression, action, severity, and description from each file.
 * Exported as a flat array of PolicySummary objects for use in demo mode.
 */
import type { PolicySummary } from '../stores/policy-store';

// Load all policy YAMLs as raw strings at build time
const rawPolicies = import.meta.glob(
  '../../../policies/imported/**/*.yaml',
  { query: '?raw', import: 'default', eager: true },
) as Record<string, string>;

function extractField(yaml: string, key: string): string {
  const match = yaml.match(new RegExp(`${key}:\\s*(.+)`));
  return match ? match[1].trim().replace(/^['"]|['"]$/g, '') : '';
}

function extractMultilineField(yaml: string, key: string): string {
  // Handles `key: |` multiline blocks — grab up to the next top-level key
  const match = yaml.match(new RegExp(`${key}:\\s*\\|?\\s*\\n((?:[ \\t]+.+\\n?)+)`));
  if (!match) return extractField(yaml, key);
  return match[1].replace(/^[ \t]+/gm, '').trim();
}

function extractExpression(yaml: string): string {
  // Match `expression: tool == ...` — handles single or double quotes
  const match = yaml.match(/expression:\s*(.+)/);
  if (!match) return '';
  let expr = match[1].trim();
  // Strip surrounding quotes if present
  if ((expr.startsWith('"') && expr.endsWith('"')) ||
      (expr.startsWith("'") && expr.endsWith("'"))) {
    expr = expr.slice(1, -1);
  }
  return expr;
}

function pathToId(path: string): string {
  // e.g. "../../../policies/imported/falco/falco-foo.yaml" → "falco/falco-foo"
  const parts = path.replace(/^.*policies\/imported\//, '').replace(/\.yaml$/, '');
  return parts;
}

function severityAnnotation(yaml: string): string {
  return extractField(yaml, 'aegis.io/severity') || extractField(yaml, 'severity') || 'medium';
}

function sourceLabel(id: string): string {
  const prefix = id.split('/')[0];
  const labels: Record<string, string> = {
    falco: 'Falco',
    kyverno: 'Kyverno',
    'opa-gatekeeper': 'OPA Gatekeeper',
    agentwall: 'AgentWall',
    'catalog-generated': 'Catalog',
    'claude-guardrails': 'Claude Guardrails',
  };
  return labels[prefix] ?? prefix;
}

let _cached: PolicySummary[] | null = null;

export function getAllImportedPolicies(bundleVersion: number = 1): PolicySummary[] {
  if (_cached) return _cached.map(p => ({ ...p, bundleVersion }));

  const policies: PolicySummary[] = [];

  for (const [path, yaml] of Object.entries(rawPolicies)) {
    if (typeof yaml !== 'string') continue;

    const id = pathToId(path);
    const name = extractField(yaml, 'name');
    const expression = extractExpression(yaml);
    const severity = severityAnnotation(yaml); void severity;
    const description = extractMultilineField(yaml, 'description');
    const source = sourceLabel(id);

    // Skip IMPORT_TODO policies (untranslatable, expression is "false")
    // Still include them but mark clearly
    const isStub = expression === 'false' || expression === '';

    policies.push({
      id,
      name: name || id.split('/').pop() || id,
      layer: 'cel',
      enabled: !isStub,
      bundleVersion,
      celExpression: isStub ? undefined : expression,
      description: `[${source}] ${description || name}`.slice(0, 200),
    });
  }

  // Sort: enabled first, then by id
  policies.sort((a, b) => {
    if (a.enabled !== b.enabled) return a.enabled ? -1 : 1;
    return a.id.localeCompare(b.id);
  });

  _cached = policies;
  return policies;
}

export function getEnabledPolicyCount(): number {
  return getAllImportedPolicies().filter(p => p.enabled).length;
}

export function getTotalPolicyCount(): number {
  return getAllImportedPolicies().length;
}
