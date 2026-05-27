import type { SecurityLabel } from '../../types/aegis';
import { confidentialityToLevel, categoriesToStrings } from '../../lib/label-display';
import styles from './SecurityLabelBadge.module.css';

export interface SecurityLabelBadgeProps {
  label: SecurityLabel;
  variant?: 'compact' | 'expanded';
  className?: string;
}

function badgeColorClass(label: SecurityLabel): string {
  if (label.categories !== 0) return styles.badgeTainted;
  if (label.confidentiality > 0) return styles.badgeConf;
  if (label.integrity > 0) return styles.badgeInt;
  return styles.badgeNeutral;
}

function buildAriaLabel(label: SecurityLabel): string {
  const confLevel = confidentialityToLevel(label.confidentiality);
  const intLevel = confidentialityToLevel(label.integrity);
  const cats = categoriesToStrings(label.categories);
  const catPart = cats.length > 0 ? `, categories: ${cats.join(', ')}` : '';
  return (
    `Security label: confidentiality ${confLevel} (${label.confidentiality}), ` +
    `integrity ${intLevel} (${label.integrity})${catPart}`
  );
}

export function SecurityLabelBadge({ label, variant = 'compact', className }: SecurityLabelBadgeProps) {
  if (variant === 'compact') {
    const colorClass = badgeColorClass(label);
    const confLevel = confidentialityToLevel(label.confidentiality);
    const cats = categoriesToStrings(label.categories);
    const display = cats.length > 0 ? `${confLevel}{${cats.join(',')}}` : confLevel;
    return (
      <span
        className={`${styles.badge} ${colorClass}${className ? ` ${className}` : ''}`}
        aria-label={buildAriaLabel(label)}
        role="img"
      >
        {display}
      </span>
    );
  }

  return (
    <div
      className={`${styles.card}${className ? ` ${className}` : ''}`}
      aria-label={buildAriaLabel(label)}
      role="img"
    >
      <div className={styles.dim}>
        <span className={styles.dimLabel}>C</span>
        <span className={`${styles.dimValue} ${label.confidentiality > 0 ? styles.confElevated : styles.dimValueNeutral}`}>
          {confidentialityToLevel(label.confidentiality)} ({label.confidentiality})
        </span>
      </div>
      <div className={styles.dim}>
        <span className={styles.dimLabel}>I</span>
        <span className={`${styles.dimValue} ${label.integrity > 0 ? styles.intElevated : styles.dimValueNeutral}`}>
          {confidentialityToLevel(label.integrity)} ({label.integrity})
        </span>
      </div>
      <div className={styles.dim}>
        <span className={styles.dimLabel}>K</span>
        <span className={`${styles.dimValue} ${label.categories !== 0 ? styles.catTainted : styles.dimValueNeutral}`}>
          {label.categories !== 0
            ? categoriesToStrings(label.categories).join(', ') || `0x${label.categories.toString(16)}`
            : '—'}
        </span>
      </div>
    </div>
  );
}
