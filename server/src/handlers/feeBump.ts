import StellarSdk, { Transaction } from "@stellar/stellar-sdk";
import { Config, FeePayerAccount, pickFeePayerAccount } from "../config";
import { NextFunction, Request, Response } from "express";
import { AppError } from "../errors/AppError";
import { ApiKeyConfig } from "../middleware/apiKeys";
import { Tenant, syncTenantFromApiKey } from "../models/tenantStore";
import { recordSponsoredTransaction } from "../models/transactionLedger";
import { FeeBumpRequest, FeeBumpSchema, FeeBumpBatchRequest, FeeBumpBatchSchema } from "../schemas/feeBump";
import { checkTenantDailyQuota } from "../services/quota";
import { calculateFeeBumpFee } from "../utils/feeCalculator";
import { verifyXdrNetwork } from "../utils/networkVerification";
import { MockPriceOracle, validateSlippage } from "../utils/priceOracle";
import { transactionMilestoneService } from "../services/discordMilestones";
import { transactionStore } from "../workers/transactionStore";

export interface FeeBumpResponse {
  xdr: string;
  status: "ready" | "submitted";
  hash?: string;
  fee_payer: string;
  submitted_via?: string;
  submission_attempts?: number;
}

async function maybeNotifyMilestones(): Promise<void> {
  try {
    await transactionMilestoneService.checkForMilestones();
  } catch (error) {
    console.error("Discord milestone check failed:", error);
  }
}

async function processFeeBump(
  xdr: string,
  submit: boolean,
  config: Config,
  tenant: Tenant,
  feePayerAccount: FeePayerAccount
): Promise<FeeBumpResponse> {
  let innerTransaction: Transaction;

  try {
    innerTransaction = StellarSdk.TransactionBuilder.fromXDR(
      xdr,
      config.networkPassphrase
    ) as Transaction;
  } catch (error: any) {
    throw new AppError(`Invalid XDR: ${error.message}`, 400, "INVALID_XDR");
  }

  if (!innerTransaction.signatures || innerTransaction.signatures.length === 0) {
    throw new AppError(
      "Inner transaction must be signed before fee-bumping",
      400,
      "UNSIGNED_TRANSACTION"
    );
  }

  if ("innerTransaction" in innerTransaction) {
    throw new AppError(
      "Cannot fee-bump an already fee-bumped transaction",
      400,
      "ALREADY_FEE_BUMPED"
    );
  }

  const operationCount = innerTransaction.operations?.length || 0;
  const feeAmount = calculateFeeBumpFee(
    innerTransaction, // Pass the transaction object for Soroban check
    config.baseFee,
    config.feeMultiplier
  );

  const quotaCheck = await checkTenantDailyQuota(tenant, feeAmount);
  if (!quotaCheck.allowed) {
    throw new AppError(
      `Tier limit exceeded. Spend ${quotaCheck.currentSpendStroops}/${quotaCheck.dailyQuotaStroops} stroops and transactions ${quotaCheck.currentTxCount}/${quotaCheck.txLimit} today.`,
      403,
      "QUOTA_EXCEEDED"
    );
  }

  const feeBumpTx = StellarSdk.TransactionBuilder.buildFeeBumpTransaction(
    feePayerAccount.keypair,
    feeAmount.toString(),
    innerTransaction,
    config.networkPassphrase
  );

  feeBumpTx.sign(feePayerAccount.keypair);
  await recordSponsoredTransaction(tenant.id, feeAmount);
  await maybeNotifyMilestones();

  const feeBumpXdr = feeBumpTx.toXDR();

  if (submit && config.horizonUrl) {
    const server = new StellarSdk.Horizon.Server(config.horizonUrl);

    try {
      const submissionResult = await server.submitTransaction(feeBumpTx);
      await transactionStore.addTransaction(submissionResult.hash, tenant.id, "submitted");

      return {
        xdr: feeBumpXdr,
        status: "submitted",
        hash: submissionResult.hash,
        fee_payer: feePayerAccount.publicKey,
      };
    } catch (error: any) {
      console.error("Transaction submission failed:", error);
      throw new AppError(
        `Transaction submission failed: ${error.message}`,
        500,
        "SUBMISSION_FAILED"
      );
    }
  }

  return {
    xdr: feeBumpXdr,
    status: submit ? "submitted" : "ready",
    fee_payer: feePayerAccount.publicKey,
  };
}

export async function feeBumpHandler(
  req: Request,
  res: Response,
  next: NextFunction,
  config: Config
): Promise<void> {
  try {
    const result = FeeBumpSchema.safeParse(req.body);

    if (!result.success) {
      console.warn(
        "Validation failed for fee-bump request:",
        result.error.format()
      );

      return next(
        new AppError(
          `Validation failed: ${JSON.stringify(result.error.format())}`,
          400,
          "INVALID_XDR"
        )
      );
    }

    const body: FeeBumpRequest = result.data;

    // Validate XDR early so errors surface before touching the signer pool
    let parsedInner: Transaction;
    try {
      parsedInner = StellarSdk.TransactionBuilder.fromXDR(
        body.xdr,
        config.networkPassphrase
      ) as Transaction;
    } catch (err: any) {
      return next(new AppError(`Invalid XDR: ${err.message}`, 400, "INVALID_XDR"));
    }
    if ("innerTransaction" in parsedInner) {
      return next(new AppError("Cannot fee-bump an already fee-bumped transaction", 400, "ALREADY_FEE_BUMPED"));
    }

    // Verify the XDR was signed for the server's configured network
    const networkCheck = verifyXdrNetwork(body.xdr, config.networkPassphrase);
    if (!networkCheck.valid) {
      return next(new AppError(networkCheck.errorMessage ?? "Network mismatch", 400, "NETWORK_MISMATCH"));
    }

    // Check against token whitelist if a token is provided
    if (body.token) {
      const supportedAssets = config.supportedAssets ?? [];
      const isWhitelisted = supportedAssets.some((asset) => {
        const assetId = asset.issuer ? `${asset.code}:${asset.issuer}` : asset.code;
        return body.token === assetId;
      });

      if (!isWhitelisted) {
        console.warn(`Rejected fee-bump request for non-whitelisted asset: ${body.token}`);
        return next(
          new AppError(
            `Whitelisting failed: Asset "${body.token}" is not accepted for fee sponsorship.`,
            400,
            "UNSUPPORTED_ASSET",
          ),
        );
      }
      console.log(`Accepted whitelisted asset: ${body.token}`);

      // Slippage protection for token payments
      if (body.maxSlippage !== undefined) {
        const priceOracle = new MockPriceOracle();
        const requestTime = Date.now();
        try {
          const currentPrice = await priceOracle.getCurrentPrice(body.token);
          const historicalPrice = await priceOracle.getHistoricalPrice(body.token, requestTime - 120000);
          const slippageCheck = validateSlippage(historicalPrice, currentPrice, body.maxSlippage);
          if (!slippageCheck.valid) {
            return next(new AppError("Slippage too high: try increasing your fee payment", 400, "SLIPPAGE_TOO_HIGH"));
          }
        } catch (error: any) {
          return next(new AppError(`Failed to verify token price: ${error.message}`, 500, "INTERNAL_ERROR"));
        }
      }
    }

    const apiKeyConfig = res.locals.apiKey as ApiKeyConfig | undefined;
    if (!apiKeyConfig) {
      res.status(500).json({
        error: "Missing tenant context for fee sponsorship",
      });
      return;
    }

    const tenant = syncTenantFromApiKey(apiKeyConfig);
    const feePayerAccount = pickFeePayerAccount(config);

    const response = await processFeeBump(
      body.xdr,
      body.submit || false,
      config,
      tenant,
      feePayerAccount
    );

    res.json(response);
  } catch (error: any) {
    console.error("Error processing fee-bump request:", error);
    next(error);
  }
}

export async function feeBumpBatchHandler(
  req: Request,
  res: Response,
  next: NextFunction,
  config: Config
): Promise<void> {
  try {
    const parsedBody = FeeBumpBatchSchema.safeParse(req.body);

    if (!parsedBody.success) {
      console.warn(
        "Validation failed for fee-bump batch request:",
        parsedBody.error.format()
      );

      return next(
        new AppError(
          `Validation failed: ${JSON.stringify(parsedBody.error.format())}`,
          400,
          "INVALID_XDR"
        )
      );
    }

    const body: FeeBumpBatchRequest = parsedBody.data;

    const apiKeyConfig = res.locals.apiKey as ApiKeyConfig | undefined;
    if (!apiKeyConfig) {
      res.status(500).json({ error: "Missing tenant context for fee sponsorship" });
      return;
    }

    const tenant = syncTenantFromApiKey(apiKeyConfig);
    const feePayerAccount = pickFeePayerAccount(config);
    const results: FeeBumpResponse[] = await Promise.all(
      body.xdrs.map((xdr) => processFeeBump(xdr, body.submit ?? false, config, tenant, feePayerAccount))
    );

    res.json(results);
  } catch (error: any) {
    console.error("Error processing fee-bump batch request:", error);
    next(error);
  }
}

