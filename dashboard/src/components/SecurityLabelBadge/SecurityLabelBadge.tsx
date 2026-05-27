import type { SecurityLabel } from '../../types/aegis';
import { confidentialityToLevel, categoriesToStrings } from '../../lib/label-display';
import styles from './SecurityLabelBadge.module.css';

export interface SecurityLabelBadgeProps {
  label: SecurityLabel;
  variant?: 'compact' | 'expanded';
  className?: string;
}

function badgeColorClass(label: SecurityLabel, s: typeof styles): string {
  if (label.category !== 0) return s.badgeTainted;
  if (label.confidentiality > 0) return s.badgeConf;
  if (label.integrity > 0) return s.badgeInt;
  return s.badgeNeutral;
}

function ariaLabel(label: SecurityLabel): string {
  const cats = categoriesToStrings(label.category);
  const level = confidentialityToLevel(label.confidentiality);
  const catPart = cats.length > 0 ? `, categories: ${cats.join(', ')}` : '';
  return `Security label: confidentiality ${level} (${label.confidentiality}), integrity ${label.integrity}${catPart}`;
}

export function SecurityLabelBadge({ label, variant = 'compact', className }: SecurityLabelBadgeProps) {
  if (variant === 'compact') {
    const colorClass = badgeColorClass(label, styles);
    const level = confidentialityToLevel(label.confidentiality);
    const cats = categoriesToStrings(label.category);
    const display = cats.length > 0 ? `${level}{${cats.join(',')}}` : level;
    return (
      <span
        className={`${styles.badge} ${colorClass}${className ? ` ${className}` : ''}`}
        aria-label={ariaLabel(label)}
        role="img"
      >
        {display}
      </span>
    );
  }

  return (
    <div
      className={`${styles.card}${className ? ` ${className}` : ''}`}
      aria-label={ariaLabel(label)}
      role="img"
    >
      <div className={styles.dim}>
        <span className={styles.dimLabel}>C</span>
        <span className={`${styles.dimValue} ${label.confidentiality > 0 ? styles.confElevated : styles.neutral}`}>
          {confidentialityToLevel(label.confidentiality)} ({label.confidentiality})
        </span>
      </div>
      <div className={styles.dim}>
        <span className={styles.dimLabel}>I</span>
        <span className={`${styles.dimValue} ${label.integrity > 0 ? styles.intElevated : styles.neutral}`}>
          {label.integrity}
        </span>
      </div>
      <div className={styles.dim}>
        <span className={styles.dimLabel}>K</span>
        <span className={`${styles.dimValue} ${label.category !== 0 ? styles.catTainted : styles.neutral}`}>
          {label.category !== 0
            ? categoriesToStrings(label.category).join(', ') || `0x${label.category.toString(16)}`
            : '—'}
        </span>
      </div>
    </div>
  );
}
