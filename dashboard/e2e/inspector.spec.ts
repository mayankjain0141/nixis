import { test, expect } from '@playwright/test';

test.describe('Inspector Panel', () => {
  test('inspector sidebar is visible', async ({ page }) => {
    await page.goto('/');
    const inspector = page.locator('[aria-label="Inspector panel"]');
    await expect(inspector).toBeVisible();
  });
});
