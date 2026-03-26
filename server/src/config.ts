import { SignerPool } from "./signing";
import StellarSdk from "@stellar/stellar-sdk";

export type HorizonSelectionStrategy = "priority" | "round_robin";

export interface FeePayerAccount {
  publicKey: string;
  keypair: ReturnType<typeof StellarSdk.Keypair.fromSecret>;
  secretSource:
  | { type: "env"; secret: string }
  | { type: "vault"; secretPath: string };
}

export interface VaultConfig {
  addr: string;
  token?: string;
  appRole?: {
    roleId: string;
    secretId: string;
  };
  kvMount: string;
  kvVersion: 1 | 2;
  secretField: string;
}

export interface Config {
  feePayerAccounts: FeePayerAccount[];
  signerPool: SignerPool;
  baseFee: number;
  feeMultiplier: number;
  networkPassphrase: string;
  horizonUrl?: string;
  rateLimitWindowMs: number;
  rateLimitMax: number;
  allowedOrigins: string[];
  alerting: AlertingConfig;
}

export interface AlertEmailConfig {
  host: string;
  port: number;
  secure: boolean;
  user?: string;
  pass?: string;
  from: string;
  to: string[];
}

export interface AlertingConfig {
  lowBalanceThresholdXlm?: number;
  checkIntervalMs: number;
  cooldownMs: number;
  slackWebhookUrl?: string;
  email?: AlertEmailConfig;
}

export function loadConfig (): Config {
  const baseFee = parseInt(process.env.FLUID_BASE_FEE || "100", 10);
  const feeMultiplier = parseFloat(process.env.FLUID_FEE_MULTIPLIER || "2.0");
  const networkPassphrase =
    process.env.STELLAR_NETWORK_PASSPHRASE ||
    "Test SDF Network ; September 2015";
  const configuredHorizonUrls = parseCommaSeparatedList(
    process.env.STELLAR_HORIZON_URLS
  );
  const legacyHorizonUrl = process.env.STELLAR_HORIZON_URL?.trim();
  const horizonUrls =
    configuredHorizonUrls.length > 0
      ? configuredHorizonUrls
      : legacyHorizonUrl
        ? [legacyHorizonUrl]
        : [];
  const horizonSelectionStrategy: HorizonSelectionStrategy =
    process.env.FLUID_HORIZON_SELECTION === "round_robin"
      ? "round_robin"
      : "priority";
  const rateLimitWindowMs = parseInt(
    process.env.FLUID_RATE_LIMIT_WINDOW_MS || "60000",
    10
  );
  const rateLimitMax = parseInt(process.env.FLUID_RATE_LIMIT_MAX || "5", 10);
  const allowedOrigins = parseCommaSeparatedList(process.env.FLUID_ALLOWED_ORIGINS);
  const maxXdrSize = parseInt(process.env.FLUID_MAX_XDR_SIZE || "10240", 10);
  const maxOperations = parseInt(process.env.FLUID_MAX_OPERATIONS || "100", 10);
  const vault = loadVaultConfig();

  const sharedConfig = {
    allowedOrigins,
    baseFee,
    feeMultiplier,
    horizonSelectionStrategy,
    horizonUrl: horizonUrls[0],
    horizonUrls,
    maxOperations,
    maxXdrSize,
    networkPassphrase,
    rateLimitMax,
    rateLimitWindowMs,
    stellarRpcUrl: process.env.STELLAR_RPC_URL,
    vault,
  };

  const vaultSecretPaths = parseCommaSeparatedList(
    process.env.FLUID_FEE_PAYER_VAULT_SECRET_PATHS
  );
  const vaultPublicKeys = parseCommaSeparatedList(
    process.env.FLUID_FEE_PAYER_PUBLIC_KEYS
  );

  if (vault && vaultSecretPaths.length > 0 && vaultPublicKeys.length > 0) {
    if (vaultSecretPaths.length !== vaultPublicKeys.length) {
      throw new Error(
        "Vault mode requires FLUID_FEE_PAYER_VAULT_SECRET_PATHS and FLUID_FEE_PAYER_PUBLIC_KEYS to have the same number of entries"
      );
    }

    const feePayerAccounts: FeePayerAccount[] = vaultPublicKeys.map(
      (publicKey, index) => ({
        publicKey,
        keypair: StellarSdk.Keypair.fromPublicKey(publicKey),
        secretSource: {
          type: "vault",
          secretPath: vaultSecretPaths[index],
        },
      })
    );

    const signerPool = new SignerPool(
      feePayerAccounts.map((account) => ({
        keypair: account.keypair,
        secret:
          account.secretSource.type === "vault"
            ? `vault:${account.secretSource.secretPath}`
            : account.secretSource.secret,
      }))
    );

    return {
      ...sharedConfig,
      feePayerAccounts,
      signerPool,
    };
  }

  const secrets = parseCommaSeparatedList(process.env.FLUID_FEE_PAYER_SECRET);
  if (secrets.length === 0) {
    throw new Error(
      "No fee payer secrets configured. Provide either Vault settings (VAULT_ADDR + token/approle + FLUID_FEE_PAYER_VAULT_SECRET_PATHS + FLUID_FEE_PAYER_PUBLIC_KEYS) or set FLUID_FEE_PAYER_SECRET for env-based development."
    );
  }

  const feePayerAccounts: FeePayerAccount[] = secrets.map((secret) => {
    const keypair = StellarSdk.Keypair.fromSecret(secret);

    return {
      publicKey: keypair.publicKey(),
      keypair,
      secretSource: { type: "env", secret },
    };
  });

  const baseFee = parseInt(process.env.FLUID_BASE_FEE || "100", 10);
  const feeMultiplier = parseFloat(process.env.FLUID_FEE_MULTIPLIER || "2.0");
  const networkPassphrase =
    process.env.STELLAR_NETWORK_PASSPHRASE ||
    "Test SDF Network ; September 2015";
  const horizonUrl = process.env.STELLAR_HORIZON_URL;
  const rateLimitWindowMs = parsePositiveInt(
    process.env.FLUID_RATE_LIMIT_WINDOW_MS,
    60_000,
  );
  const rateLimitMax = parsePositiveInt(
    process.env.FLUID_RATE_LIMIT_MAX,
    5,
  );
  const allowedOrigins = parseAllowedOrigins(process.env.FLUID_ALLOWED_ORIGINS);
  const lowBalanceThresholdXlm = parseOptionalNumber(
    process.env.FLUID_LOW_BALANCE_THRESHOLD_XLM,
  );
  const checkIntervalMs = parsePositiveInt(
    process.env.FLUID_LOW_BALANCE_CHECK_INTERVAL_MS,
    60 * 60 * 1000,
  );
  const cooldownMs = parsePositiveInt(
    process.env.FLUID_LOW_BALANCE_ALERT_COOLDOWN_MS,
    6 * 60 * 60 * 1000,
  );
  const slackWebhookUrl = process.env.FLUID_ALERT_SLACK_WEBHOOK_URL?.trim();
  const email = loadAlertEmailConfig();

  return {
    ...sharedConfig,
    feePayerAccounts,
    baseFee,
    feeMultiplier,
    networkPassphrase,
    horizonUrl,
    rateLimitWindowMs,
    rateLimitMax,
    allowedOrigins,
    alerting: {
      lowBalanceThresholdXlm,
      checkIntervalMs,
      cooldownMs,
      slackWebhookUrl: slackWebhookUrl || undefined,
      email,
    },
  };
}

function loadAlertEmailConfig(): AlertEmailConfig | undefined {
  const host = process.env.FLUID_ALERT_SMTP_HOST?.trim();
  const from = process.env.FLUID_ALERT_EMAIL_FROM?.trim();
  const to = process.env.FLUID_ALERT_EMAIL_TO
    ?.split(",")
    .map((value) => value.trim())
    .filter(Boolean);

  if (!host || !from || !to || to.length === 0) {
    return undefined;
  }

  return {
    host,
    port: parsePositiveInt(process.env.FLUID_ALERT_SMTP_PORT, 587),
    secure: process.env.FLUID_ALERT_SMTP_SECURE === "true",
    user: process.env.FLUID_ALERT_SMTP_USER?.trim() || undefined,
    pass: process.env.FLUID_ALERT_SMTP_PASS?.trim() || undefined,
    from,
    to,
  };
}

function parsePositiveInt(
  value: string | undefined,
  fallback: number,
): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseOptionalNumber(value: string | undefined): number | undefined {
  if (!value) {
    return undefined;
  }

  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : undefined;
}

function parseAllowedOrigins(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  return value
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

// Round-robin counter (module-level, safe for single-threaded Node.js event loop)
let rrIndex = 0;

export function pickFeePayerAccount (config: Config): FeePayerAccount {
  const snapshot = config.signerPool.getSnapshot();
  const nextPublicKey = snapshot[rrIndex % snapshot.length]?.publicKey;
  rrIndex = (rrIndex + 1) % snapshot.length;
  const account = config.feePayerAccounts.find(
    (candidate) => candidate.publicKey === nextPublicKey
  );

  if (!account) {
    throw new Error("Failed to select fee payer account from signer pool");
  }

  return account;
}
