import { describe, expect, it, vi } from "vitest";

import type { Config } from "../config";
import StellarSdk from "@stellar/stellar-sdk";

vi.mock("../signing/native", () => ({
  nativeSigner: {
    preflightSoroban: vi.fn(),
    signPayload: vi.fn(async () => Buffer.alloc(64)),
    signPayloadFromVault: vi.fn(async () => Buffer.alloc(64)),
  },
}));

describe("feeBumpHandler", () => {
  it("rejects an already fee-bumped transaction", async () => {
    const { feeBumpHandler } = await import("./feeBump");

    const sourceKeypair = StellarSdk.Keypair.random();
    const feePayerKeypair = StellarSdk.Keypair.random();

    const networkPassphrase = StellarSdk.Networks.TESTNET;
    const baseFee = 100;

    const sourceAccount = new StellarSdk.Account(
      sourceKeypair.publicKey(),
      "1",
    );

    const innerTransaction = new StellarSdk.TransactionBuilder(sourceAccount, {
      fee: String(baseFee),
      networkPassphrase,
    })
      .addOperation(
        StellarSdk.Operation.payment({
          destination: sourceKeypair.publicKey(),
          asset: StellarSdk.Asset.native(),
          amount: "10",
        }),
      )
      .setTimeout(0)
      .build();
    innerTransaction.sign(sourceKeypair);

    const feeBumpTx = StellarSdk.TransactionBuilder.buildFeeBumpTransaction(
      feePayerKeypair.publicKey(),
      200,
      innerTransaction,
      networkPassphrase,
    );
    feeBumpTx.sign(feePayerKeypair);

    const feeBumpXdr = feeBumpTx.toXDR();

    const config: Config = {
      feePayerAccounts: [
        {
          publicKey: feePayerKeypair.publicKey(),
          keypair: feePayerKeypair,
          secretSource: {
            type: "env",
            secret: feePayerKeypair.secret(),
          },
        },
      ],
      signerPool: {
        acquire: async () => ({
          account: {
            keypair: feePayerKeypair,
            publicKey: feePayerKeypair.publicKey(),
            secret: feePayerKeypair.secret(),
          },
          release: async () => undefined,
          reservedSequenceNumber: null,
        }),
        getSnapshot: () => [],
      } as any,
      baseFee,
      feeMultiplier: 2,
      networkPassphrase,
      horizonUrl: undefined,
      horizonUrls: [],
      horizonSelectionStrategy: "priority",
      allowedOrigins: ["*"],
      maxOperations: 100,
      maxXdrSize: 10240,
      rateLimitWindowMs: 60_000,
      rateLimitMax: 5,
    };

    const req: any = {
      body: {
        xdr: feeBumpXdr,
        submit: false,
      },
    };

    const res: any = {
      locals: {
        apiKey: {
          tenantId: "tenant-1",
          tier: "pro",
          apiKey: "test-key",
          dailyQuotaStroops: 1_000_000,
          perMinuteLimit: 10,
        },
      },
    };

    let nextErr: any;
    const next = (err: any) => {
      nextErr = err;
    };

    await feeBumpHandler(req, res, config, next as any);

    expect(nextErr).toBeTruthy();
    expect(nextErr.statusCode).toBe(400);
    expect(nextErr.message).toBe(
      "Cannot fee-bump an already fee-bumped transaction",
    );
  });
});

