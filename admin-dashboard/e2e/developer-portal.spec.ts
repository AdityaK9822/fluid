import { expect, test } from "@playwright/test";

test.describe("Developer portal landing", () => {
  test("shows hero, features, SDK snippet, footer links, and Get API key CTA", async ({
    page,
  }) => {
    await page.goto("/");

    await expect(
      page.getByRole("heading", {
        name: /Ship gasless Stellar experiences at scale/i,
      }),
    ).toBeVisible();

    await expect(page.getByRole("link", { name: /Get API Key/i })).toHaveAttribute(
      "href",
      "/login",
    );

    await expect(
      page.getByRole("heading", { name: /Gasless by design/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: /Multi-asset flows/i }),
    ).toBeVisible();
    await expect(
      page.getByRole("heading", { name: /Soroban-ready/i }),
    ).toBeVisible();

    await expect(page.getByRole("heading", { name: /Integrate in minutes/i })).toBeVisible();
    await expect(page.getByText("FluidClient")).toBeVisible();
    await expect(page.getByText("requestFeeBump")).toBeVisible();

    const footer = page.getByRole("contentinfo");
    await expect(footer.getByRole("link", { name: /^Documentation$/i })).toHaveAttribute(
      "href",
      /^https?:\/\//,
    );
    await expect(footer.getByRole("link", { name: /^GitHub$/i })).toHaveAttribute(
      "href",
      /^https?:\/\//,
    );
    await expect(footer.getByRole("link", { name: /^Discord$/i })).toHaveAttribute(
      "href",
      /^https?:\/\//,
    );
  });

  test("embeds JSON-LD for WebSite", async ({ page }) => {
    await page.goto("/");
    const ld = await page.locator('script[type="application/ld+json"]').textContent();
    expect(ld).toBeTruthy();
    const parsed = JSON.parse(ld!);
    expect(parsed["@type"]).toBe("WebSite");
    expect(parsed.name).toContain("Fluid");
  });
});
