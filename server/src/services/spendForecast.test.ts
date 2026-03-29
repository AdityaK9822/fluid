import { describe, expect, it } from "vitest";
import { calculateSpendForecast } from "./spendForecast";

const STROOPS_PER_XLM = 10_000_000n;

function buildDailyTransactions(now: Date, dailyXlmSpend: number) {
  const transactions: Array<{ createdAt: Date; costStroops: bigint }> = [];

  for (let offset = 0; offset < 30; offset += 1) {
    const createdAt = new Date(now);
    createdAt.setUTCDate(createdAt.getUTCDate() - offset);

    transactions.push({
      createdAt,
      costStroops: BigInt(dailyXlmSpend) * STROOPS_PER_XLM,
    });
  }

  return transactions;
}

describe("calculateSpendForecast", () => {
  it("computes runway close to 14 days for 140 XLM balance and 10 XLM/day spend", () => {
    const now = new Date("2026-03-28T12:00:00.000Z");
    const result = calculateSpendForecast({
      currentBalanceStroops: 140n * STROOPS_PER_XLM,
      now,
      transactions: buildDailyTransactions(now, 10),
    });

    expect(result.runwayDays).not.toBeNull();
    expect(result.runwayDays).toBeGreaterThanOrEqual(13.5);
    expect(result.runwayDays).toBeLessThanOrEqual(14.5);
    expect(result.alert).toBe(false);
    expect(result.projectedBalance.length).toBeGreaterThan(1);
  });

  it("raises alert when projected runway drops below 7 days", () => {
    const now = new Date("2026-03-28T12:00:00.000Z");
    const result = calculateSpendForecast({
      currentBalanceStroops: 50n * STROOPS_PER_XLM,
      now,
      transactions: buildDailyTransactions(now, 10),
    });

    expect(result.runwayDays).not.toBeNull();
    expect(result.runwayDays).toBeLessThan(7);
    expect(result.alert).toBe(true);
  });
});
