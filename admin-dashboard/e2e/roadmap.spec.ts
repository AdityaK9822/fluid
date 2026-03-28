import { expect, test } from "@playwright/test";

test.describe("Roadmap voting board", () => {
  test("renders hero, status filters, and roadmap items", async ({ page }) => {
    await page.goto("/roadmap");

    // Hero
    await expect(
      page.getByRole("heading", { name: /Shape what we build next/i }),
    ).toBeVisible();

    // Status filter tabs
    await expect(page.getByRole("button", { name: /^All$/i })).toBeVisible();
    await expect(
      page.getByRole("button", { name: /^Planned$/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /^In Progress$/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("button", { name: /^Shipped$/i }),
    ).toBeVisible();

    // At least one roadmap item card is visible
    await expect(page.getByRole("article").first()).toBeVisible();

    // Vote buttons are present
    const voteButtons = page.getByRole("button", {
      name: /Vote for|Remove vote/i,
    });
    await expect(voteButtons.first()).toBeVisible();
  });

  test("navbar contains Roadmap link", async ({ page }) => {
    await page.goto("/");
    const nav = page.getByRole("navigation").first();
    await expect(nav.getByRole("link", { name: /^Roadmap$/i })).toHaveAttribute(
      "href",
      "/roadmap",
    );
  });

  test("portal footer contains Roadmap link", async ({ page }) => {
    await page.goto("/");
    const footer = page.getByRole("contentinfo");
    await expect(
      footer.getByRole("link", { name: /^Roadmap$/i }),
    ).toHaveAttribute("href", "/roadmap");
  });

  test("filtering by Planned shows only planned items", async ({ page }) => {
    await page.goto("/roadmap");

    // Wait for items to load
    await expect(page.getByRole("article").first()).toBeVisible();

    await page.getByRole("button", { name: /^Planned$/i }).click();

    // All visible status badges should be "Planned"
    const badges = page.locator("article span", { hasText: /^Planned$/ });
    await expect(badges.first()).toBeVisible();

    // No "In Progress" or "Shipped" badges should be visible
    await expect(
      page.locator("article span", { hasText: /^In Progress$/ }),
    ).toHaveCount(0);
    await expect(
      page.locator("article span", { hasText: /^Shipped$/ }),
    ).toHaveCount(0);
  });

  test("filtering by Shipped shows only shipped items", async ({ page }) => {
    await page.goto("/roadmap");
    await expect(page.getByRole("article").first()).toBeVisible();

    await page.getByRole("button", { name: /^Shipped$/i }).click();

    const badges = page.locator("article span", { hasText: /^Shipped$/ });
    await expect(badges.first()).toBeVisible();
    await expect(
      page.locator("article span", { hasText: /^Planned$/ }),
    ).toHaveCount(0);
  });

  test("vote button toggles and updates count", async ({ page }) => {
    await page.goto("/roadmap");

    // Wait for items and SSO token to be ready
    await expect(page.getByRole("article").first()).toBeVisible();
    // Give the SSO token fetch a moment
    await page.waitForTimeout(500);

    const firstVoteBtn = page
      .getByRole("button", { name: /Vote for|Remove vote/i })
      .first();
    const initialLabel = await firstVoteBtn.getAttribute("aria-label");
    const initialCount = parseInt(
      initialLabel?.match(/(\d+) votes/)?.[1] ?? "0",
    );

    await firstVoteBtn.click();

    // After voting, count should change by 1
    await expect(firstVoteBtn).toHaveAttribute(
      "aria-label",
      new RegExp(`${initialCount + 1} votes`),
    );
    await expect(firstVoteBtn).toHaveAttribute("aria-pressed", "true");

    // Click again to unvote
    await firstVoteBtn.click();
    await expect(firstVoteBtn).toHaveAttribute(
      "aria-label",
      new RegExp(`${initialCount} votes`),
    );
    await expect(firstVoteBtn).toHaveAttribute("aria-pressed", "false");
  });

  test("SSO token endpoint returns a token", async ({ request }) => {
    const res = await request.get(
      "/api/roadmap/sso-token?userId=test-user-123",
    );
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(typeof body.token).toBe("string");
    expect(body.token.split(".")).toHaveLength(3);
  });

  test("items API returns roadmap items", async ({ request }) => {
    const res = await request.get("/api/roadmap/items");
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(Array.isArray(body.items)).toBe(true);
    expect(body.items.length).toBeGreaterThan(0);
    const item = body.items[0];
    expect(item).toHaveProperty("id");
    expect(item).toHaveProperty("title");
    expect(item).toHaveProperty("status");
    expect(item).toHaveProperty("votes");
    expect(item).toHaveProperty("hasVoted");
  });

  test("vote API requires a token", async ({ request }) => {
    const res = await request.post("/api/roadmap/vote", {
      data: { itemId: "batch-fee-bump" },
    });
    expect(res.status()).toBe(401);
  });

  test("vote API accepts a valid token and toggles vote", async ({
    request,
  }) => {
    // Get a token
    const tokenRes = await request.get(
      "/api/roadmap/sso-token?userId=e2e-voter",
    );
    const { token } = await tokenRes.json();

    // Vote
    const voteRes = await request.post("/api/roadmap/vote", {
      data: { itemId: "batch-fee-bump", token },
    });
    expect(voteRes.status()).toBe(200);
    const voteBody = await voteRes.json();
    expect(typeof voteBody.votes).toBe("number");
    expect(voteBody.hasVoted).toBe(true);

    // Unvote
    const unvoteRes = await request.post("/api/roadmap/vote", {
      data: { itemId: "batch-fee-bump", token },
    });
    expect(unvoteRes.status()).toBe(200);
    const unvoteBody = await unvoteRes.json();
    expect(unvoteBody.hasVoted).toBe(false);
  });

  test("admin status update requires auth", async ({ request }) => {
    const res = await request.patch("/api/admin/roadmap/batch-fee-bump", {
      data: { status: "shipped" },
    });
    expect(res.status()).toBe(401);
  });
});
