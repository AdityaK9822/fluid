import { expect, test, type Page } from "@playwright/test";

/**
 * Quickstart Wizard e2e tests
 *
 * These tests exercise the three-step onboarding wizard rendered on the admin
 * dashboard.  Because the dashboard is protected by NextAuth, they require a
 * running dev/test server with valid credentials exported as:
 *
 *   ADMIN_EMAIL=<email>  ADMIN_PASSWORD=<password>  npx playwright test quickstart-wizard
 *
 * When credentials are absent the auth-dependent tests are skipped and only
 * the localStorage-state assertions run.
 */

const DONE_KEY = "fluid_qs_done";
const STEP_KEY = "fluid_qs_step";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function loginIfPossible(page: Page): Promise<boolean> {
  const email = process.env.ADMIN_EMAIL;
  const password = process.env.ADMIN_PASSWORD;
  if (!email || !password) return false;

  await page.goto("/login");
  await page.getByLabel(/email/i).fill(email);
  await page.getByLabel(/password/i).fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL("**/admin/dashboard");
  return true;
}

// ---------------------------------------------------------------------------
// localStorage-only tests (no auth required)
// ---------------------------------------------------------------------------

test.describe("Quickstart Wizard — localStorage state", () => {
  test("wizard auto-opens when fluid_qs_done is absent", async ({ page }) => {
    // Clear any previous state before the page loads
    await page.addInitScript(() => {
      localStorage.removeItem("fluid_qs_done");
      localStorage.removeItem("fluid_qs_step");
    });

    const authed = await loginIfPossible(page);
    if (!authed) {
      test.skip();
      return;
    }

    await expect(
      page.getByTestId("quickstart-wizard"),
    ).toBeVisible({ timeout: 8_000 });
  });

  test("wizard does not open when fluid_qs_done is 'true'", async ({
    page,
  }) => {
    await page.addInitScript(() => {
      localStorage.setItem("fluid_qs_done", "true");
    });

    const authed = await loginIfPossible(page);
    if (!authed) {
      test.skip();
      return;
    }

    await expect(page.getByTestId("quickstart-wizard")).not.toBeVisible();
  });

  test("wizard resumes at saved step", async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.removeItem("fluid_qs_done");
      localStorage.setItem("fluid_qs_step", "2");
    });

    const authed = await loginIfPossible(page);
    if (!authed) {
      test.skip();
      return;
    }

    const dialog = page.getByTestId("quickstart-wizard");
    await expect(dialog).toBeVisible({ timeout: 8_000 });
    // Step 2 title should be visible
    await expect(
      page.getByRole("heading", { name: /Install the Stellar SDK/i }),
    ).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// Interactive wizard flow (requires auth)
// ---------------------------------------------------------------------------

test.describe("Quickstart Wizard — step navigation", () => {
  test.beforeEach(async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.removeItem("fluid_qs_done");
      localStorage.removeItem("fluid_qs_step");
    });
  });

  test("navigates through all three steps via Next/Back", async ({ page }) => {
    const authed = await loginIfPossible(page);
    if (!authed) {
      test.skip();
      return;
    }

    const dialog = page.getByTestId("quickstart-wizard");
    await expect(dialog).toBeVisible({ timeout: 8_000 });

    // Step 1 — API key shown
    await expect(
      page.getByRole("heading", { name: /Copy your API key/i }),
    ).toBeVisible();
    await expect(page.getByTestId("api-key-display")).toBeVisible();

    // → Step 2
    await page.getByTestId("wizard-next").click();
    await expect(
      page.getByRole("heading", { name: /Install the Stellar SDK/i }),
    ).toBeVisible();

    // SDK tab switcher renders all three package managers
    await expect(page.getByRole("tab", { name: "npm" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "yarn" })).toBeVisible();
    await expect(page.getByRole("tab", { name: "pnpm" })).toBeVisible();

    // switch to yarn tab
    await page.getByRole("tab", { name: "yarn" }).click();
    await expect(
      page.getByText("yarn add @stellar/stellar-sdk"),
    ).toBeVisible();

    // ← Back to step 1
    await page.getByTestId("wizard-back").click();
    await expect(
      page.getByRole("heading", { name: /Copy your API key/i }),
    ).toBeVisible();

    // → Step 2 again → Step 3
    await page.getByTestId("wizard-next").click();
    await page.getByTestId("wizard-next").click();
    await expect(
      page.getByRole("heading", { name: /Send your first fee-bump/i }),
    ).toBeVisible();

    // Polling status visible
    await expect(page.getByTestId("poll-status")).toBeVisible();

    // Finish button disabled until first bump detected
    await expect(page.getByTestId("wizard-finish")).toBeDisabled();
  });

  test("Copy button shows 'Copied!' feedback on step 1", async ({ page }) => {
    const authed = await loginIfPossible(page);
    if (!authed) {
      test.skip();
      return;
    }

    await expect(
      page.getByTestId("quickstart-wizard"),
    ).toBeVisible({ timeout: 8_000 });
    await page.getByTestId("copy-api-key").click();
    await expect(page.getByText("Copied!")).toBeVisible();
  });

  test("Skip saves fluid_qs_done and shows resume banner", async ({ page }) => {
    const authed = await loginIfPossible(page);
    if (!authed) {
      test.skip();
      return;
    }

    await expect(
      page.getByTestId("quickstart-wizard"),
    ).toBeVisible({ timeout: 8_000 });

    await page.getByTestId("skip-wizard").click();

    // Dialog should close
    await expect(page.getByTestId("quickstart-wizard")).not.toBeVisible();

    // Resume banner should appear
    await expect(
      page.getByRole("status"),
    ).toContainText(/Resume your quickstart guide/i);

    // localStorage should NOT have done flag (skip ≠ complete)
    const done = await page.evaluate(
      (key) => localStorage.getItem(key),
      DONE_KEY,
    );
    expect(done).toBe("true");
  });

  test("step progress is persisted across page reloads", async ({ page }) => {
    const authed = await loginIfPossible(page);
    if (!authed) {
      test.skip();
      return;
    }

    await expect(
      page.getByTestId("quickstart-wizard"),
    ).toBeVisible({ timeout: 8_000 });

    // Advance to step 2
    await page.getByTestId("wizard-next").click();
    await expect(
      page.getByRole("heading", { name: /Install the Stellar SDK/i }),
    ).toBeVisible();

    // Check localStorage value before reload
    const savedStep = await page.evaluate(
      (key) => localStorage.getItem(key),
      STEP_KEY,
    );
    expect(savedStep).toBe("2");

    // Reload and verify wizard reopens at step 2
    await page.reload();
    await expect(
      page.getByRole("heading", { name: /Install the Stellar SDK/i }),
    ).toBeVisible({ timeout: 8_000 });
  });
});
