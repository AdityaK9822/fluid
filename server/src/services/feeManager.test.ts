import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import type { Config } from "../config";
import { initializeFeeManager, resetFeeManagerForTests } from "./feeManager";

const mockFetch = vi.fn();

vi.stubGlobal("fetch", mockFetch);

function buildConfig(): Config {
  return {
    baseFee: 100,
    feeMultiplier: 2,
    horizonUrl: "https://horizon.example.test",
  } as Config;
}

describe("FeeManager", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetFeeManagerForTests();
  });

  afterEach(() => {
    resetFeeManagerForTests();
  });

  it("switches to low multiplier under low congestion", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ fee_charged: { p70: "90", p95: "120" } }),
    });

    const manager = initializeFeeManager(buildConfig());
    manager.stop();

    await manager.pollOnce();

    expect(manager.getMultiplier()).toBe(1);
    expect(manager.getSnapshot().congestionLevel).toBe("low");
  });

  it("switches to high multiplier under high congestion", async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ fee_charged: { p70: "300", p95: "800" } }),
    });

    const manager = initializeFeeManager(buildConfig());
    manager.stop();

    await manager.pollOnce();

    expect(manager.getMultiplier()).toBe(2);
    expect(manager.getSnapshot().congestionLevel).toBe("high");
  });
});
