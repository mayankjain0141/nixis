// P0 security invariant: deny-verdict DOM elements must NEVER display in green (--allow color).
// Operators seeing a DENY rendered green could mistake it for an ALLOW — a safety violation.

import { useEffect } from 'react';

interface Violation {
  element: Element;
  computedColor: string;
  detectedAt: number;
}

export class DenyColorGuardService {
  private observer: MutationObserver | null = null;
  readonly violations: Violation[] = [];

  start(): void {
    if (typeof window === 'undefined' || typeof MutationObserver === 'undefined') return;
    this.check();
    this.observer = new MutationObserver(() => this.check());
    this.observer.observe(document.body, {
      subtree: true,
      attributes: true,
      attributeFilter: ['data-verdict', 'style', 'class'],
    });
  }

  stop(): void {
    this.observer?.disconnect();
    this.observer = null;
  }

  check(): void {
    if (typeof document === 'undefined') return;
    const denyElements = document.querySelectorAll('[data-verdict="deny"]');
    for (const el of denyElements) {
      const style = window.getComputedStyle(el);
      // --allow green: #2da44e = rgb(45, 164, 78)
      const colorProps = [style.color, style.backgroundColor, style.borderColor, style.borderLeftColor];
      for (const color of colorProps) {
        if (this.isAllowGreen(color)) {
          this.violations.push({ element: el, computedColor: color, detectedAt: Date.now() });
          console.error('[DenyColorGuard] VIOLATION: deny element uses allow-green color', el, color);
        }
      }
    }
  }

  private isAllowGreen(color: string): boolean {
    if (!color || color === 'transparent' || color === 'rgba(0, 0, 0, 0)') return false;
    // Match rgb(45, 164, 78) or #2da44e
    return (
      color === 'rgb(45, 164, 78)' ||
      color.toLowerCase() === '#2da44e' ||
      color.includes('45, 164, 78')
    );
  }

  clearViolations(): void {
    this.violations.length = 0;
  }
}

export const guardInstance = new DenyColorGuardService();

export function DenyColorGuard(): null {
  useEffect(() => {
    guardInstance.start();
    return () => guardInstance.stop();
  }, []);
  return null;
}
