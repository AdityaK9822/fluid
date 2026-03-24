import StellarSdk from "@stellar/stellar-sdk";

export interface Config {
  feePayerSecret: string;
  feePayerPublicKey: string;
  baseFee: number;
  feeMultiplier: number;
  networkPassphrase: string;
  horizonUrl?: string;
  rateLimitWindowMs: number;
  rateLimitMax: number;
  allowedOrigins: string[];
}

export function loadConfig(): Config {
  const feePayerSecret = process.env.FLUID_FEE_PAYER_SECRET;
  if (!feePayerSecret) {
    throw new Error("FLUID_FEE_PAYER_SECRET environment variable is required");
  }

  const feePayerKeypair = StellarSdk.Keypair.fromSecret(feePayerSecret);
  const feePayerPublicKey = feePayerKeypair.publicKey();

  const baseFee = parseInt(process.env.FLUID_BASE_FEE || "100", 10);
  const feeMultiplier = parseFloat(process.env.FLUID_FEE_MULTIPLIER || "2.0");
  const networkPassphrase =
    process.env.STELLAR_NETWORK_PASSPHRASE ||
    "Test SDF Network ; September 2015";
  const horizonUrl = process.env.STELLAR_HORIZON_URL;

  const rateLimitWindowMs = parseInt(
    process.env.FLUID_RATE_LIMIT_WINDOW_MS || "60000",
    10
  );
  const rateLimitMax = parseInt(process.env.FLUID_RATE_LIMIT_MAX || "5", 10);
  // Parse allowed origins from comma-separated environment variable
  const allowedOriginsEnv = process.env.ALLOWED_ORIGINS || "";
  const allowedOrigins = allowedOriginsEnv
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  return {
    feePayerSecret,
    feePayerPublicKey,
    baseFee,
    feeMultiplier,
    networkPassphrase,
    horizonUrl,
    rateLimitWindowMs,
    rateLimitMax,
    allowedOrigins,
  };
}
