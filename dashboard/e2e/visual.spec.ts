import { test, expect } from '@playwright/test';

test.describe('Visual regression', () => {
  test('dashboard screenshot matches baseline', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);
    await expect(page).toHaveScreenshot('dashboard-baseline.png', {
      maxDiffPixelRatio: 0.02,
      mask: [page.locator('[data-testid="timestamp"]')],
    });
  });
});
