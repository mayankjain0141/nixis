import { test, expect } from '@playwright/test';

test.describe('Visual regression', () => {
  test('dashboard screenshot matches baseline', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(500);
    // Run with: npx playwright test --update-snapshots  (first run only, to create baseline)
    await expect(page).toHaveScreenshot('dashboard-full.png', {
      threshold: 0.001,
      animations: 'disabled',
      mask: [page.locator('[data-testid="timestamp"]'), page.locator('time')],
    });
  });
});
