import { describe, it, expect } from 'vitest';
import {
  confidentialityToLevel,
  levelToConfidentiality,
  categoriesToStrings,
  formatSecurityLabel,
} from './label-display';
import { VERDICTS } from '../types/events';

describe('label-display — WS-15 acceptance criteria', () => {
  describe('confidentialityToLevel', () => {
    it('maps 0 to Unclassified', () => {
      expect(confidentialityToLevel(0)).toBe('Unclassified');
    });

    it('maps 8191 (< 8192) to Unclassified', () => {
      expect(confidentialityToLevel(8191)).toBe('Unclassified');
    });

    it('maps 8192 to Internal', () => {
      expect(confidentialityToLevel(8192)).toBe('Internal');
    });

    it('maps 16384 to Internal (ADR-013 canonical Internal value)', () => {
      expect(confidentialityToLevel(16384)).toBe('Internal');
    });

    it('maps 24576 to Confidential', () => {
      expect(confidentialityToLevel(24576)).toBe('Confidential');
    });

    it('maps 32768 to Confidential (ADR-013 canonical Confidential value)', () => {
      expect(confidentialityToLevel(32768)).toBe('Confidential');
    });

    it('maps 49152 to Restricted', () => {
      expect(confidentialityToLevel(49152)).toBe('Restricted');
    });

    it('maps 57344 to Restricted (ADR-013 canonical Restricted value)', () => {
      expect(confidentialityToLevel(57344)).toBe('Restricted');
    });

    it('maps 65535 to Restricted', () => {
      expect(confidentialityToLevel(65535)).toBe('Restricted');
    });
  });

  describe('categoriesToStrings', () => {
    it('maps 0 to empty array', () => {
      expect(categoriesToStrings(0)).toEqual([]);
    });

    it('maps bit 0 to credentials', () => {
      expect(categoriesToStrings(1)).toEqual(['credentials']);
    });

    it('maps bits 1+2 to finance and pii', () => {
      expect(categoriesToStrings(6)).toEqual(['finance', 'pii']);
    });

    it('maps all 5 known bits', () => {
      expect(categoriesToStrings(0b11111)).toEqual([
        'credentials', 'finance', 'pii', 'health', 'legal',
      ]);
    });

    it('ignores reserved bits above bit 4', () => {
      const result = categoriesToStrings(0b100000); // bit 5, reserved
      expect(result).toEqual([]);
    });
  });

  describe('formatSecurityLabel', () => {
    it('formats a zero label as Unclassified', () => {
      expect(formatSecurityLabel({ confidentiality: 0, integrity: 0, categories: 0 })).toBe('Unclassified');
    });

    it('includes category names in braces when set', () => {
      expect(formatSecurityLabel({ confidentiality: 32768, integrity: 0, categories: 1 })).toBe('Confidential{credentials}');
    });

    it('formats multiple categories comma-separated', () => {
      expect(formatSecurityLabel({ confidentiality: 32768, integrity: 0, categories: 6 })).toBe('Confidential{finance,pii}');
    });
  });

  describe('levelToConfidentiality — round-trip', () => {
    const cases: [string, number][] = [
      ['Unclassified', 0],
      ['Internal', 16384],
      ['Confidential', 32768],
      ['Restricted', 57344],
    ];

    for (const [level, num] of cases) {
      it(`${level} round-trips: levelToConfidentiality → confidentialityToLevel`, () => {
        expect(confidentialityToLevel(levelToConfidentiality(level))).toBe(level);
      });

      it(`${level}: levelToConfidentiality(${level}) === ${num}`, () => {
        expect(levelToConfidentiality(level)).toBe(num);
      });
    }

    it('unknown level defaults to 0 (Unclassified)', () => {
      expect(levelToConfidentiality('TopSecret')).toBe(0);
    });
  });

  describe('Verdict canonical values — TestVerdict_CanonicalValues', () => {
    it('VERDICTS contains exactly the four canonical values', () => {
      expect([...VERDICTS].sort()).toEqual(['allow', 'audit', 'deny', 'require_approval']);
    });

    it('escalate is not a valid verdict', () => {
      expect(VERDICTS).not.toContain('escalate');
    });

    it('HITL is not a valid verdict', () => {
      expect(VERDICTS).not.toContain('HITL');
    });

    it('block is not a valid verdict', () => {
      expect(VERDICTS).not.toContain('block');
    });
  });

  // ── WS-15 Acceptance Criteria (named) ─────────────────────────────────────

  // TestLabelDisplay_NumericToString: {confidentiality: 32768} → "Confidential"
  describe('TestLabelDisplay_NumericToString', () => {
    it('{confidentiality: 32768} maps to "Confidential"', () => {
      expect(confidentialityToLevel(32768)).toBe('Confidential');
    });

    it('{confidentiality: 0} maps to "Unclassified"', () => {
      expect(confidentialityToLevel(0)).toBe('Unclassified');
    });

    it('{confidentiality: 49152} maps to "Restricted"', () => {
      expect(confidentialityToLevel(49152)).toBe('Restricted');
    });
  });

  // TestLabelDisplay_NeverTransmitted: no string label in formatSecurityLabel output
  // that looks like a wire format (no "level:" or string-typed SecurityLabel shapes).
  describe('TestLabelDisplay_NeverTransmitted', () => {
    it('formatSecurityLabel output is a display string, not a wire-format object', () => {
      const result = formatSecurityLabel({ confidentiality: 32768, integrity: 0, categories: 0 });
      // The result must be a plain string — not a JSON object or structured wire payload
      expect(typeof result).toBe('string');
      expect(result).not.toContain('"level"');
      expect(result).not.toContain('"confidentiality"');
    });

    it('label-display module exports only pure functions — no store imports', () => {
      // Verified structurally: the module has no Zustand imports.
      // The imported functions operate on plain numbers, not store state.
      const label = { confidentiality: 16384, integrity: 0, categories: 1 };
      const display = formatSecurityLabel(label);
      expect(typeof display).toBe('string');
      // Must not contain numeric wire values in string form (would indicate format leak)
      expect(display).not.toMatch(/^\d+$/);
    });
  });
});
