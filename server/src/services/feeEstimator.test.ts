import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Config } from "../config";

vi.mock("./priceService", () => ({
  priceService: {
    getTokenPriceUsd: vi.fn().mockResolvedValue({ toString: () => "0.12" }),
  },
}));

vi.mock("./feeManager", async () => {
  const actual = await vi.importActual<typeof import("./feeManager")>("./feeManager");
  return {
    ...actual,
    getFeeManager: vi.fn(() => null),
  };
});

import { estimateFeeFromDescription } from "./feeEstimator";

function buildConfig(): Config {
  return {
    baseFee: 100,
    feeMultiplier: 2,
  } as Config;
}

describe("estimateFeeFromDescription", () => {
  beforeEach(() => {
    delete process.env.OPENAI_API_KEY;
  });

  afterEach(() => {
    delete process.env.OPENAI_API_KEY;
  });

  it("returns a fallback estimate when OpenAI key is not set", async () => {
    const estimate = await estimateFeeFromDescription(
      "USDC transfer to 3 accounts via Soroban",
      buildConfig()
    );

    expect(estimate.source).toBe("fallback");
    expect(estimate.operationCount).toBe(3);
    expect(estimate.estimatedStroops).toBeGreaterThan(0);
    expect(estimate.estimatedUsd).toBeGreaterThan(0);
  });
});
