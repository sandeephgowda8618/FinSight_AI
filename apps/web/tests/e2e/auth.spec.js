const { test, expect } = require("@playwright/test");

test("browser login, generic rejection, protected session, and logout use the live API", async ({ page }) => {
  const email = process.env.E2E_EMAIL;
  const password = process.env.E2E_PASSWORD;
  if (!email || !password) throw new Error("E2E_EMAIL and E2E_PASSWORD must be supplied by the disposable smoke runner");

  const unauthorized = page.waitForResponse((response) => response.url().endsWith("/auth/me") && response.status() === 401);
  await page.goto("/");
  await unauthorized;
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(`${password}-wrong`);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Email or password is incorrect.")).toBeVisible();

  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("status").filter({ hasText: email })).toBeVisible();
  expect(await page.evaluate(() => document.cookie)).not.toContain("finsight_session");

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  const replay = page.waitForResponse((response) => response.url().endsWith("/auth/me") && response.status() === 401);
  await page.reload();
  await replay;
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});
