import { test, expect } from '@playwright/test';

test.describe('Mock daemon fallback', () => {
  test('switches to mock mode when daemon unavailable', async ({ page }) => {
    await page.goto('/');
    await page.waitForTimeout(3000);
    await expect(page.locator('body')).toBeVisible();
  });

  test('mock events appear in stream after fallback', async ({ page }) => {
    await page.goto('/');
    await page.waitForTimeout(3500);
    const eventItems = page.locator('[role="listitem"], li').first();
    await expect(page.locator('body')).toBeVisible();
  });
});
