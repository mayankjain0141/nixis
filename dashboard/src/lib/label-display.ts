// The ONLY location in the frontend that converts numeric SecurityLabel to display strings.
// All other code uses numeric values. ADR-013 canonical mapping.
import type { SecurityLabel } from '../types/aegis';

export function confidentialityToLevel(c: number): string {
  if (c < 8192) return 'Unclassified';
  if (c < 24576) return 'Internal';
  if (c < 49152) return 'Confidential';
  return 'Restricted';
}

export function levelToConfidentiality(level: string): number {
  switch (level) {
    case 'Unclassified': return 0;
    case 'Internal': return 16384;
    case 'Confidential': return 32768;
    case 'Restricted': return 57344;
    default: return 0;
  }
}

const CATEGORY_NAMES = ['credentials', 'finance', 'pii', 'health', 'legal'] as const;

export function categoriesToStrings(bitmask: number): string[] {
  return CATEGORY_NAMES.filter((_name, i) => (bitmask & (1 << i)) !== 0);
}

export function formatSecurityLabel(label: SecurityLabel): string {
  const level = confidentialityToLevel(label.confidentiality);
  const cats = categoriesToStrings(label.categories);
  if (cats.length === 0) return level;
  return `${level}{${cats.join(',')}}`;
}
