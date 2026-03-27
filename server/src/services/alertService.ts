import type { AlertEmailConfig, AlertingConfig, Config } from "../config";
import { SlackNotifier, type SlackNotifierLike } from "./slackNotifier";

type NodeMailerModule = {
  createTransport: (config: {
    host: string;
    port: number;
    secure: boolean;
    auth?: { user: string; pass: string };
  }) => {
    sendMail: (message: {
      from: string;
      to: string;
      subject: string;
      text: string;
      html: string;
    }) => Promise<unknown>;
  };
};

export interface LowBalanceAlertPayload {
  accountPublicKey: string;
  balanceXlm: number;
  thresholdXlm: number;
  networkPassphrase: string;
  horizonUrl?: string;
  checkedAt: Date;
}

interface AlertState {
  currentlyLow: boolean;
  lastAlertAt?: number;
}

export class AlertService {
  private readonly state = new Map<string, AlertState>();

  constructor(
    private readonly config: AlertingConfig,
    private readonly slackNotifier: SlackNotifierLike = new SlackNotifier({
      webhookUrl: config.slackWebhookUrl,
    }),
  ) {}

  isEnabled(): boolean {
    return Boolean(this.config.email) || this.slackNotifier.isConfigured();
  }

  async sendLowBalanceAlert(payload: LowBalanceAlertPayload): Promise<boolean> {
    if (!this.isEnabled()) {
      return false;
    }

    const alertState = this.state.get(payload.accountPublicKey) ?? {
      currentlyLow: false,
    };
    const now = Date.now();
    const shouldSend =
      !alertState.currentlyLow ||
      !alertState.lastAlertAt ||
      now - alertState.lastAlertAt >= this.config.cooldownMs;

    this.state.set(payload.accountPublicKey, {
      currentlyLow: true,
      lastAlertAt: shouldSend ? now : alertState.lastAlertAt,
    });

    if (!shouldSend) {
      return false;
    }

    await this.notifyAdmins(payload);
    return true;
  }

  markBalanceRecovered(accountPublicKey: string): void {
    const existing = this.state.get(accountPublicKey);
    if (!existing) {
      return;
    }

    this.state.set(accountPublicKey, {
      currentlyLow: false,
      lastAlertAt: existing.lastAlertAt,
    });
  }

  async sendTestAlert(appConfig: Config): Promise<void> {
    const firstAccount = appConfig.feePayerAccounts[0];
    const thresholdXlm = appConfig.alerting.lowBalanceThresholdXlm ?? 0;

    await this.notifyAdmins({
      accountPublicKey: firstAccount?.publicKey ?? "GTESTALERTPLACEHOLDER",
      balanceXlm: thresholdXlm > 0 ? Math.max(0, thresholdXlm - 0.01) : 0.99,
      thresholdXlm: thresholdXlm > 0 ? thresholdXlm : 1,
      networkPassphrase: appConfig.networkPassphrase,
      horizonUrl: appConfig.horizonUrl,
      checkedAt: new Date(),
    });
  }

  private async notifyAdmins(payload: LowBalanceAlertPayload): Promise<void> {
    const tasks: Array<Promise<void>> = [];

    if (this.slackNotifier.isEnabled("low_balance")) {
      tasks.push(
        this.slackNotifier.notifyLowBalance(payload).then((sent) => {
          if (!sent) {
            throw new Error("Slack low-balance alert could not be delivered.");
          }
        }),
      );
    }

    if (this.config.email) {
      tasks.push(this.sendEmailAlert(payload, this.config.email));
    }

    if (tasks.length === 0) {
      return;
    }

    const results = await Promise.allSettled(tasks);
    const failures = results.filter(
      (result): result is PromiseRejectedResult => result.status === "rejected",
    );

    if (failures.length === results.length) {
      throw new Error(
        `All alert transports failed: ${failures.map((item) => item.reason).join("; ")}`,
      );
    }

    failures.forEach((failure) => {
      console.error("[AlertService] Alert transport failed:", failure.reason);
    });
  }

  private async sendEmailAlert(
    payload: LowBalanceAlertPayload,
    emailConfig: AlertEmailConfig,
  ): Promise<void> {
    const nodemailer = this.loadNodeMailer();
    const transport = nodemailer.createTransport({
      host: emailConfig.host,
      port: emailConfig.port,
      secure: emailConfig.secure,
      auth:
        emailConfig.user && emailConfig.pass
          ? {
              user: emailConfig.user,
              pass: emailConfig.pass,
            }
          : undefined,
    });

    await transport.sendMail({
      from: emailConfig.from,
      to: emailConfig.to.join(", "),
      subject: `[Fluid] Low fee payer balance: ${payload.balanceXlm.toFixed(2)} XLM`,
      text: this.buildPlainTextMessage(payload),
      html: this.buildHtmlMessage(payload),
    });
  }

  private loadNodeMailer(): NodeMailerModule {
    try {
      return require("nodemailer") as NodeMailerModule;
    } catch (error) {
      throw new Error(
        "Email alerting requires the 'nodemailer' package to be installed.",
      );
    }
  }

  private buildPlainTextMessage(payload: LowBalanceAlertPayload): string {
    const lines = [
      "Fluid low balance alert",
      "",
      `Fee payer: ${payload.accountPublicKey}`,
      `Current balance: ${payload.balanceXlm.toFixed(7)} XLM`,
      `Threshold: ${payload.thresholdXlm.toFixed(7)} XLM`,
      `Network: ${payload.networkPassphrase}`,
      `Checked at: ${payload.checkedAt.toISOString()}`,
    ];

    if (payload.horizonUrl) {
      lines.push(`Horizon: ${payload.horizonUrl}`);
    }

    lines.push("", "Top up the fee payer account before sponsorship stops.");
    return lines.join("\n");
  }

  private buildHtmlMessage(payload: LowBalanceAlertPayload): string {
    const horizonLine = payload.horizonUrl
      ? `<p><strong>Horizon:</strong> ${escapeHtml(payload.horizonUrl)}</p>`
      : "";

    return [
      "<h2>Fluid low balance alert</h2>",
      `<p><strong>Fee payer:</strong> ${escapeHtml(payload.accountPublicKey)}</p>`,
      `<p><strong>Current balance:</strong> ${payload.balanceXlm.toFixed(7)} XLM</p>`,
      `<p><strong>Threshold:</strong> ${payload.thresholdXlm.toFixed(7)} XLM</p>`,
      `<p><strong>Network:</strong> ${escapeHtml(payload.networkPassphrase)}</p>`,
      `<p><strong>Checked at:</strong> ${escapeHtml(payload.checkedAt.toISOString())}</p>`,
      horizonLine,
      "<p>Top up the fee payer account before sponsorship stops.</p>",
    ].join("");
  }
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
