import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SlackNotifier } from "./slackNotifier";

describe("SlackNotifier", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockResolvedValue({
      ok: true,
      text: vi.fn().mockResolvedValue("ok"),
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    fetchMock.mockReset();
  });

  it("posts Block Kit low-balance messages with severity, timestamp, and detail", async () => {
    const notifier = new SlackNotifier({
      webhookUrl: "https://hooks.slack.test/services/example",
    });
    const checkedAt = new Date("2026-03-27T12:00:00.000Z");

    const sent = await notifier.notifyLowBalance({
      accountPublicKey: "GLOWBALANCEEXAMPLE",
      balanceXlm: 0.42,
      checkedAt,
      horizonUrl: "https://horizon-testnet.stellar.org",
      networkPassphrase: "Testnet",
      thresholdXlm: 5,
    });

    expect(sent).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const [, request] = fetchMock.mock.calls[0];
    const payload = JSON.parse(String(request?.body));

    expect(payload.blocks[0].text.text).toContain("⚠️ Low balance alert");
    expect(JSON.stringify(payload.blocks)).toContain(checkedAt.toISOString());
    expect(JSON.stringify(payload.blocks)).toContain("GLOWBALANCEEXAMPLE");
    expect(JSON.stringify(payload.blocks)).toContain("0.4200000 XLM");
  });

  it("posts 5xx error alerts with the configured severity emoji", async () => {
    const notifier = new SlackNotifier({
      webhookUrl: "https://hooks.slack.test/services/example",
    });
    const timestamp = new Date("2026-03-27T12:01:00.000Z");

    const sent = await notifier.notifyServerError({
      errorMessage: "Transaction submission failed",
      method: "POST",
      path: "/fee-bump",
      requestId: "req-123",
      statusCode: 500,
      timestamp,
    });

    expect(sent).toBe(true);
    const [, request] = fetchMock.mock.calls[0];
    const payload = JSON.parse(String(request?.body));

    expect(payload.blocks[0].text.text).toContain("🚨 5xx server error");
    expect(JSON.stringify(payload.blocks)).toContain("POST /fee-bump");
    expect(JSON.stringify(payload.blocks)).toContain(timestamp.toISOString());
  });

  it("posts lifecycle alerts for server starts and stops", async () => {
    const notifier = new SlackNotifier({
      webhookUrl: "https://hooks.slack.test/services/example",
    });
    const timestamp = new Date("2026-03-27T12:02:00.000Z");

    const sent = await notifier.notifyServerLifecycle({
      detail: "Listening on http://0.0.0.0:3000",
      phase: "start",
      timestamp,
    });

    expect(sent).toBe(true);
    const [, request] = fetchMock.mock.calls[0];
    const payload = JSON.parse(String(request?.body));

    expect(payload.blocks[0].text.text).toContain("🟢 Server started");
    expect(JSON.stringify(payload.blocks)).toContain(
      "Listening on http://0.0.0.0:3000",
    );
  });

  it("respects per-event toggles for failed transaction alerts", async () => {
    const notifier = new SlackNotifier({
      toggles: {
        failedTransaction: false,
      },
      webhookUrl: "https://hooks.slack.test/services/example",
    });

    const sent = await notifier.notifyFailedTransaction({
      detail: "Horizon marked the transaction unsuccessful.",
      source: "ledger_monitor",
      tenantId: "tenant-1",
      timestamp: new Date("2026-03-27T12:03:00.000Z"),
      transactionHash: "abc123",
    });

    expect(sent).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
