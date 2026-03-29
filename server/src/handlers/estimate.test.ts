import { describe, expect, it, vi } from "vitest";
import type { Config } from "../config";

vi.mock("../services/feeEstimator", () => ({
  estimateFeeFromDescription: vi.fn().mockResolvedValue({
    confidence: "high",
    estimatedStroops: 12345,
    estimatedUsd: 0.000148,
    estimatedXlm: 0.0012345,
    multiplierUsed: 1,
    notes: "mock",
    operationCount: 2,
    operationTypes: ["payment"],
    source: "openai",
    sorobanResourceFeeStroops: 0,
  }),
}));

import { estimateFeeHandler } from "./estimate";

function makeRes() {
  const res = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
  };

  return res as any;
}

describe("estimateFeeHandler", () => {
  it("returns fee estimate for valid description", async () => {
    const req = {
      body: { description: "USDC transfer to 3 accounts via Soroban" },
    } as any;
    const res = makeRes();
    const next = vi.fn();

    await estimateFeeHandler({ baseFee: 100 } as Config)(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.json).toHaveBeenCalledWith(
      expect.objectContaining({ estimatedStroops: 12345 })
    );
  });

  it("returns 400 for invalid body", async () => {
    const req = {
      body: { description: "no" },
    } as any;
    const res = makeRes();
    const next = vi.fn();

    await estimateFeeHandler({ baseFee: 100 } as Config)(req, res, next);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(next).not.toHaveBeenCalled();
  });
});
