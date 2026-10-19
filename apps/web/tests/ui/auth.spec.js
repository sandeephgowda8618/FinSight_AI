const { test, expect } = require("@playwright/test");

test.beforeEach(async ({ page }) => {
  let signedIn = false;
  await page.route("**/api/runtime-config", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ apiBaseUrl: "http://127.0.0.1:8100" }),
  }));
  await page.route("http://127.0.0.1:8100/auth/me", (route) => route.fulfill({
    status: signedIn ? 200 : 401,
    contentType: "application/json",
    body: signedIn
      ? JSON.stringify({ user_id: "11111111-1111-4111-8111-111111111111", email: "analyst@example.test", display_name: "Synthetic Analyst" })
      : JSON.stringify({ detail: "Authentication required" }),
  }));
  await page.route("http://127.0.0.1:8100/auth/login", async (route) => {
    const payload = route.request().postDataJSON();
    if (payload.password !== "correct synthetic password") {
      return route.fulfill({ status: 401, contentType: "application/json", body: JSON.stringify({ detail: "Email or password is incorrect." }) });
    }
    signedIn = true;
    return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ user_id: "11111111-1111-4111-8111-111111111111", email: payload.email, display_name: "Synthetic Analyst" }) });
  });
  await page.route("http://127.0.0.1:8100/auth/logout", async (route) => {
    signedIn = false;
    await route.fulfill({ status: 204, body: "" });
  });
});

test("login reports a generic error and success enables logout", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Email").fill("analyst@example.test");
  await page.getByLabel("Password").fill("wrong synthetic password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Email or password is incorrect.")).toBeVisible();

  await page.getByLabel("Password").fill("correct synthetic password");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Signed in as Synthetic Analyst" })).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
});

test("service outage is visible and the form remains usable", async ({ page }) => {
  await page.route("**/api/runtime-config", (route) => route.fulfill({ status: 503, contentType: "application/json", body: "{}" }));
  await page.goto("/");
  await expect(page.getByText("Authentication service is unavailable.")).toBeVisible();
  await expect(page.getByLabel("Email")).toBeVisible();
});
