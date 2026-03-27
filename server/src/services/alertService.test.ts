import { describe, expect, it, vi } from "vitest";
import { AlertService } from "./alertService";
import type { SlackNotifierLike } from "./slackNotifier";

function createSlackNotifierMock(): SlackNotifierLike {
  return {
    isConfigured: vi.fn().mockReturnValue(true),
    isEnabled: vi.fn().mockReturnValue(true),
    notifyFailedTransaction: vi.fn().mockResolvedValue(true),
    notifyLowBalance: vi.fn().mockResolvedValue(true),
    notifyServerError: vi.fn().mockResolvedValue(true),
    notifyServerLifecycle: vi.fn().mockResolvedValue(true),
  };
}

describe("AlertService", () => {
  it("delegates low-balance alerts to the Slack notifier", async () => {
    const notifier = createSlackNotifierMock();
    const service = new AlertService(
      {
        checkIntervalMs: 60_000,
        cooldownMs: 3_600_000,
      },
      notifier,
    );

    const sent = await service.sendLowBalanceAlert({
      accountPublicKey: "GLOWBALANCEEXAMPLE",
      balanceXlm: 1.25,
      checkedAt: new Date("2026-03-27T12:04:00.000Z"),
      networkPassphrase: "Testnet",
      thresholdXlm: 5,
    });

    expect(sent).toBe(true);
    expect(notifier.notifyLowBalance).toHaveBeenCalledTimes(1);
  });

  it("suppresses duplicate low-balance alerts inside the cooldown window", async () => {
    const notifier = createSlackNotifierMock();
    const service = new AlertService(
      {
        checkIntervalMs: 60_000,
        cooldownMs: 3_600_000,
      },
      notifier,
    );
    const payload = {
      accountPublicKey: "GLOWBALANCEEXAMPLE",
      balanceXlm: 0.75,
      checkedAt: new Date("2026-03-27T12:05:00.000Z"),
      networkPassphrase: "Testnet",
      thresholdXlm: 5,
    };

    expect(await service.sendLowBalanceAlert(payload)).toBe(true);
    expect(await service.sendLowBalanceAlert(payload)).toBe(false);
    expect(notifier.notifyLowBalance).toHaveBeenCalledTimes(1);
  });
});
