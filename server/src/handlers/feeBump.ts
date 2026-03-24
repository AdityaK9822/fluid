import { Request, Response, NextFunction } from "express";
import StellarSdk from "@stellar/stellar-sdk";
import { Config } from "../config";
import { AppError } from "../errors/AppError";

import { FeeBumpSchema, FeeBumpRequest } from "../schemas/feeBump";

interface FeeBumpResponse {
  xdr: string;
  status: string;
  hash?: string;
}

export function feeBumpHandler(
  req: Request,
  res: Response,
  next: NextFunction,
  config: Config
): void {
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

    console.log("Received fee-bump request");

    let innerTransaction: any;
    try {
      innerTransaction = StellarSdk.TransactionBuilder.fromXDR(
        body.xdr,
        config.networkPassphrase
      );
    } catch (error: any) {
      console.error("Failed to parse XDR:", error.message);
      return next(
        new AppError(`Invalid XDR: ${error.message}`, 400, "INVALID_XDR")
      );
    }

    // Verify inner transaction is signed
    if (innerTransaction.signatures.length === 0) {
      return next(
        new AppError(
          "Inner transaction must be signed before fee-bumping",
          400,
          "UNSIGNED_TRANSACTION"
        )
      );
    }

    if ("feeBumpTransaction" in innerTransaction) {
      return next(
        new AppError(
          "Cannot fee-bump an already fee-bumped transaction",
          400,
          "ALREADY_FEE_BUMPED"
        )
      );
    }

    const feeAmount = Math.floor(config.baseFee * config.feeMultiplier);

    const feePayerKeypair = StellarSdk.Keypair.fromSecret(
      config.feePayerSecret
    );

    const feeBumpTx = StellarSdk.TransactionBuilder.buildFeeBumpTransaction(
      feePayerKeypair,
      feeAmount,
      innerTransaction,
      config.networkPassphrase
    );

    feeBumpTx.sign(feePayerKeypair);

    const feeBumpXdr = feeBumpTx.toXDR();

    console.log("Fee-bump transaction created successfully");

    const submit = body.submit || false;
    const status = submit ? "submitted" : "ready";

    if (submit && config.horizonUrl) {
      const server = new StellarSdk.Horizon.Server(config.horizonUrl);
      server
        .submitTransaction(feeBumpTx)
        .then((result: any) => {
          const response: FeeBumpResponse = {
            xdr: feeBumpXdr,
            status: "submitted",
            hash: result.hash,
          };
          res.json(response);
        })
        .catch((error: any) => {
          console.error("Transaction submission failed:", error);
          next(
            new AppError(
              `Transaction submission failed: ${error.message}`,
              500,
              "SUBMISSION_FAILED"
            )
          );
        });
    } else {
      const response: FeeBumpResponse = {
        xdr: feeBumpXdr,
        status,
      };
      res.json(response);
    }
  } catch (error: any) {
    console.error("Error processing fee-bump request:", error);
    next(error);
  }
}
