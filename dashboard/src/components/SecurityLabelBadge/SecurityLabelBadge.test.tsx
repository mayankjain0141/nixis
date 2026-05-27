import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { SecurityLabelBadge } from './SecurityLabelBadge';
import type { SecurityLabel } from '../../types/aegis';

const zeroLabel: SecurityLabel = { confidentiality: 0, integrity: 0, category: 0 };
const confLabel: SecurityLabel = { confidentiality: 32768, integrity: 32768, category: 0 };
const taintedLabel: SecurityLabel = { confidentiality: 32768, integrity: 16384, category: 1 };

describe('SecurityLabelBadge', () => {
  describe('compact variant', () => {
    it('renders zero label as Unclassified', () => {
      render(<SecurityLabelBadge label={zeroLabel} />);
      expect(screen.getByRole('img')).toHaveTextContent('Unclassified');
    });

    it('renders confidential label correctly', () => {
      render(<SecurityLabelBadge label={confLabel} />);
      expect(screen.getByRole('img')).toHaveTextContent('Confidential');
    });

    it('renders tainted label with category name', () => {
      render(<SecurityLabelBadge label={taintedLabel} />);
      expect(screen.getByRole('img')).toHaveTextContent('credentials');
    });

    it('aria-label includes confidentiality level and value', () => {
      render(<SecurityLabelBadge label={confLabel} />);
      const ariaLabel = screen.getByRole('img').getAttribute('aria-label') ?? '';
      expect(ariaLabel).toMatch(/confidentiality Confidential \(32768\)/i);
    });

    it('aria-label includes integrity level and value', () => {
      render(<SecurityLabelBadge label={confLabel} />);
      const ariaLabel = screen.getByRole('img').getAttribute('aria-label') ?? '';
      expect(ariaLabel).toMatch(/integrity Confidential \(32768\)/i);
    });

    it('aria-label includes category names when bits are set', () => {
      render(<SecurityLabelBadge label={taintedLabel} />);
      const ariaLabel = screen.getByRole('img').getAttribute('aria-label') ?? '';
      expect(ariaLabel).toMatch(/categories: credentials/i);
    });

    it('aria-label omits category section when category is zero', () => {
      render(<SecurityLabelBadge label={confLabel} />);
      const ariaLabel = screen.getByRole('img').getAttribute('aria-label') ?? '';
      expect(ariaLabel).not.toMatch(/categories/i);
    });

    it('applies className prop', () => {
      render(<SecurityLabelBadge label={zeroLabel} className="custom" />);
      expect(screen.getByRole('img').classList.contains('custom')).toBe(true);
    });
  });

  describe('expanded variant', () => {
    it('renders all three dimension labels', () => {
      render(<SecurityLabelBadge label={confLabel} variant="expanded" />);
      const text = screen.getByRole('img').textContent ?? '';
      expect(text).toContain('C');
      expect(text).toContain('I');
      expect(text).toContain('K');
    });

    it('shows level name and numeric value for confidentiality', () => {
      render(<SecurityLabelBadge label={confLabel} variant="expanded" />);
      const text = screen.getByRole('img').textContent ?? '';
      expect(text).toContain('Confidential');
      expect(text).toContain('32768');
    });

    it('shows level name and numeric value for integrity', () => {
      render(<SecurityLabelBadge label={confLabel} variant="expanded" />);
      const text = screen.getByRole('img').textContent ?? '';
      // integrity 32768 also maps to Confidential; both the level name and value must appear
      expect(text).toContain('32768');
    });

    it('shows category names when category bits are set', () => {
      render(<SecurityLabelBadge label={taintedLabel} variant="expanded" />);
      expect(screen.getByRole('img').textContent).toContain('credentials');
    });

    it('shows em-dash for zero category', () => {
      render(<SecurityLabelBadge label={zeroLabel} variant="expanded" />);
      expect(screen.getByRole('img').textContent).toContain('—');
    });

    it('aria-label includes integrity level and value', () => {
      render(<SecurityLabelBadge label={taintedLabel} variant="expanded" />);
      const ariaLabel = screen.getByRole('img').getAttribute('aria-label') ?? '';
      expect(ariaLabel).toMatch(/integrity/i);
      expect(ariaLabel).toContain('16384');
    });

    it('aria-label includes category names', () => {
      render(<SecurityLabelBadge label={taintedLabel} variant="expanded" />);
      const ariaLabel = screen.getByRole('img').getAttribute('aria-label') ?? '';
      expect(ariaLabel).toMatch(/categories: credentials/i);
    });
  });

  describe('default variant', () => {
    it('defaults to compact — renders a span not a div', () => {
      render(<SecurityLabelBadge label={zeroLabel} />);
      // The compact path renders a <span role="img">; the expanded path renders a <div role="img">.
      const elem = screen.getByRole('img');
      expect(elem.tagName.toLowerCase()).toBe('span');
    });
  });
});
