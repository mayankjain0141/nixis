import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { DenyColorGuardService } from './DenyColorGuard';

describe('DenyColorGuard', () => {
  let guard: DenyColorGuardService;

  beforeEach(() => {
    guard = new DenyColorGuardService();
    document.body.innerHTML = '';
    guard.clearViolations();
  });

  afterEach(() => {
    guard.stop();
    vi.restoreAllMocks();
  });

  it('TestVisualization_DenyNeverGreen: detects deny element with allow-green color as violation', () => {
    const el = document.createElement('div');
    el.setAttribute('data-verdict', 'deny');
    const originalGetComputedStyle = window.getComputedStyle.bind(window);
    vi.spyOn(window, 'getComputedStyle').mockImplementation((element, pseudoElt) => {
      if (element === el) {
        return {
          color: 'rgb(45, 164, 78)',
          backgroundColor: 'transparent',
          borderColor: 'transparent',
          borderLeftColor: 'transparent',
        } as unknown as CSSStyleDeclaration;
      }
      return originalGetComputedStyle(element, pseudoElt ?? undefined);
    });
    document.body.appendChild(el);

    guard.check();

    expect(guard.violations.length).toBeGreaterThan(0);
    expect(guard.violations[0].computedColor).toBe('rgb(45, 164, 78)');
    expect(guard.violations[0].element).toBe(el);
  });

  it('no violation for deny element with correct red color', () => {
    const el = document.createElement('div');
    el.setAttribute('data-verdict', 'deny');
    const originalGetComputedStyle = window.getComputedStyle.bind(window);
    vi.spyOn(window, 'getComputedStyle').mockImplementation((element, pseudoElt) => {
      if (element === el) {
        return {
          color: 'rgb(207, 34, 46)',
          backgroundColor: 'transparent',
          borderColor: 'transparent',
          borderLeftColor: 'transparent',
        } as unknown as CSSStyleDeclaration;
      }
      return originalGetComputedStyle(element, pseudoElt ?? undefined);
    });
    document.body.appendChild(el);

    guard.check();

    expect(guard.violations.length).toBe(0);
  });

  it('no violation for allow element with green color (only deny elements are checked)', () => {
    const el = document.createElement('div');
    el.setAttribute('data-verdict', 'allow');
    const originalGetComputedStyle = window.getComputedStyle.bind(window);
    vi.spyOn(window, 'getComputedStyle').mockImplementation((element, pseudoElt) => {
      if (element === el) {
        return {
          color: 'rgb(45, 164, 78)',
          backgroundColor: 'transparent',
          borderColor: 'transparent',
          borderLeftColor: 'transparent',
        } as unknown as CSSStyleDeclaration;
      }
      return originalGetComputedStyle(element, pseudoElt ?? undefined);
    });
    document.body.appendChild(el);

    guard.check();

    expect(guard.violations.length).toBe(0);
  });

  it('start() does not throw in jsdom environment', () => {
    expect(() => guard.start()).not.toThrow();
  });

  it('stop() does not throw when not started', () => {
    expect(() => guard.stop()).not.toThrow();
  });

  it('detects deny element with allow-green backgroundColor as violation', () => {
    const el = document.createElement('div');
    el.setAttribute('data-verdict', 'deny');
    const originalGetComputedStyle = window.getComputedStyle.bind(window);
    vi.spyOn(window, 'getComputedStyle').mockImplementation((element, pseudoElt) => {
      if (element === el) {
        return {
          color: 'rgb(0, 0, 0)',
          backgroundColor: 'rgb(45, 164, 78)',
          borderColor: 'transparent',
          borderLeftColor: 'transparent',
        } as unknown as CSSStyleDeclaration;
      }
      return originalGetComputedStyle(element, pseudoElt ?? undefined);
    });
    document.body.appendChild(el);

    guard.check();

    expect(guard.violations.length).toBeGreaterThan(0);
    expect(guard.violations[0].computedColor).toBe('rgb(45, 164, 78)');
  });

  it('clearViolations resets the violations array', () => {
    const el = document.createElement('div');
    el.setAttribute('data-verdict', 'deny');
    const originalGetComputedStyle = window.getComputedStyle.bind(window);
    vi.spyOn(window, 'getComputedStyle').mockImplementation((element, pseudoElt) => {
      if (element === el) {
        return {
          color: 'rgb(45, 164, 78)',
          backgroundColor: 'transparent',
          borderColor: 'transparent',
          borderLeftColor: 'transparent',
        } as unknown as CSSStyleDeclaration;
      }
      return originalGetComputedStyle(element, pseudoElt ?? undefined);
    });
    document.body.appendChild(el);
    guard.check();
    expect(guard.violations.length).toBeGreaterThan(0);

    guard.clearViolations();

    expect(guard.violations.length).toBe(0);
  });
});
