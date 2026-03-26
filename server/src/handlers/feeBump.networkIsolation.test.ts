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

describe("feeBumpHandler network isolation", () => {
  it("rejects a Mainnet XDR when server is configured for Testnet", async () => {
    const { feeBumpHandler } = await import("./feeBump");

    const sourceKeypair = StellarSdk.Keypair.random();
    const feePayerKeypair = StellarSdk.Keypair.random();

    // Create a Mainnet transaction
    const mainnetPassphrase = "Public Global Stellar Network ; September 2015";
    const testnetPassphrase = "Test SDF Network ; September 2015";

    const sourceAccount = new StellarSdk.Account(
      sourceKeypair.publicKey(),
      "1",
    );

    const innerTransaction = new StellarSdk.TransactionBuilder(sourceAccount, {
      fee: "100",
      networkPassphrase: mainnetPassphrase, // Mainnet transaction
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

    const mainnetXdr = innerTransaction.toXDR();

    // Server is configured for Testnet
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
      baseFee: 100,
      feeMultiplier: 2,
      networkPassphrase: testnetPassphrase, // Server configured for Testnet
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
        xdr: mainnetXdr,
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
    expect(nextErr.code).toBe("NETWORK_MISMATCH");
    expect(nextErr.message).toContain("Network mismatch");
    expect(nextErr.message).toContain("Mainnet");
    expect(nextErr.message).toContain("Testnet");
  });

  it("rejects a Testnet XDR when server is configured for Mainnet", async () => {
    const { feeBumpHandler } = await import("./feeBump");

    const sourceKeypair = StellarSdk.Keypair.random();
    const feePayerKeypair = StellarSdk.Keypair.random();

    // Create a Testnet transaction
    const mainnetPassphrase = "Public Global Stellar Network ; September 2015";
    const testnetPassphrase = "Test SDF Network ; September 2015";

    const sourceAccount = new StellarSdk.Account(
      sourceKeypair.publicKey(),
      "1",
    );

    const innerTransaction = new StellarSdk.TransactionBuilder(sourceAccount, {
      fee: "100",
      networkPassphrase: testnetPassphrase, // Testnet transaction
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

    const testnetXdr = innerTransaction.toXDR();

    // Server is configured for Mainnet
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
      baseFee: 100,
      feeMultiplier: 2,
      networkPassphrase: mainnetPassphrase, // Server configured for Mainnet
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
        xdr: testnetXdr,
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
    expect(nextErr.code).toBe("NETWORK_MISMATCH");
    expect(nextErr.message).toContain("Network mismatch");
    expect(nextErr.message).toContain("Testnet");
    expect(nextErr.message).toContain("Mainnet");
  });

  it("accepts a Testnet XDR when server is configured for Testnet", async () => {
    const { feeBumpHandler } = await import("./feeBump");

    const sourceKeypair = StellarSdk.Keypair.random();
    const feePayerKeypair = StellarSdk.Keypair.random();

    // Create a Testnet transaction
    const testnetPassphrase = "Test SDF Network ; September 2015";

    const sourceAccount = new StellarSdk.Account(
      sourceKeypair.publicKey(),
      "1",
    );

    const innerTransaction = new StellarSdk.TransactionBuilder(sourceAccount, {
      fee: "100",
      networkPassphrase: testnetPassphrase,
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

    const testnetXdr = innerTransaction.toXDR();

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
      baseFee: 100,
      feeMultiplier: 2,
      networkPassphrase: testnetPassphrase,
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
        xdr: testnetXdr,
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
      json: vi.fn(),
      status: vi.fn().mockReturnThis(),
    };

    let nextErr: any;
    const next = (err: any) => {
      nextErr = err;
    };

    await feeBumpHandler(req, res, config, next as any);

    // Should not have an error - the transaction should be processed
    expect(nextErr).toBeUndefined();
    // Should have returned a valid response
    expect(res.json).toHaveBeenCalled();
  });
});