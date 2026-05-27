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

    it('has accessible aria-label describing all three dimensions', () => {
      render(<SecurityLabelBadge label={confLabel} />);
      const badge = screen.getByRole('img');
      expect(badge.getAttribute('aria-label')).toMatch(/confidentiality/i);
      expect(badge.getAttribute('aria-label')).toMatch(/integrity/i);
    });

    it('applies className prop', () => {
      render(<SecurityLabelBadge label={zeroLabel} className="custom" />);
      expect(screen.getByRole('img').classList.contains('custom')).toBe(true);
    });
  });

  describe('expanded variant', () => {
    it('renders all three dimension labels', () => {
      render(<SecurityLabelBadge label={confLabel} variant="expanded" />);
      const card = screen.getByRole('img');
      expect(card.textContent).toMatch(/C/);
      expect(card.textContent).toMatch(/I/);
      expect(card.textContent).toMatch(/K/);
    });

    it('shows numeric confidentiality value in expanded mode', () => {
      render(<SecurityLabelBadge label={confLabel} variant="expanded" />);
      expect(screen.getByRole('img').textContent).toContain('32768');
    });

    it('shows category names when category bits are set', () => {
      render(<SecurityLabelBadge label={taintedLabel} variant="expanded" />);
      expect(screen.getByRole('img').textContent).toContain('credentials');
    });

    it('shows dash for zero category', () => {
      render(<SecurityLabelBadge label={zeroLabel} variant="expanded" />);
      expect(screen.getByRole('img').textContent).toContain('—');
    });

    it('has accessible aria-label', () => {
      render(<SecurityLabelBadge label={taintedLabel} variant="expanded" />);
      const card = screen.getByRole('img');
      expect(card.getAttribute('aria-label')).toMatch(/confidentiality/i);
      expect(card.getAttribute('aria-label')).toMatch(/categories: credentials/i);
    });
  });

  describe('default variant', () => {
    it('defaults to compact when variant is omitted', () => {
      const { container } = render(<SecurityLabelBadge label={zeroLabel} />);
      expect(container.querySelector('span')).not.toBeNull();
      expect(container.querySelector('div')).toBeNull();
    });
  });
});
