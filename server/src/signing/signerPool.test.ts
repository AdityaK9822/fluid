import { expect, it } from "vitest";

import { SignerPool } from "./signerPool";
import StellarSdk from "@stellar/stellar-sdk";
import { createLogger } from "../utils/logger";
import { nativeSigner } from "./native";

const logger = createLogger({ component: "signer_pool_test" });

function createDeferred (): {
  promise: Promise<void>;
  resolve (): void;
} {
  let resolve!: () => void;
  const promise = new Promise<void>((nextResolve) => {
    resolve = nextResolve;
  });

  return { promise, resolve };
}

it("SignerPool signs concurrently across five distinct accounts", async () => {
  const keypairs = Array.from({ length: 5 }, () => StellarSdk.Keypair.random());
  const pool = new SignerPool(
    keypairs.map((keypair, index) => ({
      initialSequenceNumber: BigInt(index + 1),
      keypair,
      secret: keypair.secret(),
    })),
    {
      lowBalanceThreshold: 50n,
      selectionStrategy: "least_used",
    }
  );

  await pool.updateBalance(keypairs[0].publicKey(), 500n);
  await pool.updateBalance(keypairs[1].publicKey(), 500n);
  await pool.updateBalance(keypairs[2].publicKey(), 500n);
  await pool.updateBalance(keypairs[3].publicKey(), 500n);
  await pool.updateBalance(keypairs[4].publicKey(), 500n);

  const barrier = createDeferred();
  const acquisitions: Array<{ publicKey: string; sequence: string | null; txId: string }> = [];

  const signingTasks = Array.from({ length: 5 }, (_, index) =>
    pool.withSigner(async (lease) => {
      const txId = `tx-${index + 1}`;
      const sequence = lease.reservedSequenceNumber?.toString() ?? null;
      acquisitions.push({
        publicKey: lease.account.publicKey,
        sequence,
        txId,
      });

      logger.info(
        { account: lease.account.publicKey, sequence, tx_id: txId },
        "POOL_TEST acquire"
      );

      if (acquisitions.length === 5) {
        barrier.resolve();
      }

      await barrier.promise;

      const signature = await nativeSigner.signPayload(
        lease.account.secret,
        Buffer.from(`payload-${txId}`)
      );

      logger.info(
        {
          account: lease.account.publicKey,
          signature_bytes: signature.length,
          tx_id: txId,
        },
        "POOL_TEST signed"
      );

      return {
        publicKey: lease.account.publicKey,
        sequence,
        signature: signature.toString("base64"),
        txId,
      };
    })
  );

  const results = await Promise.all(signingTasks);
  const distinctAccounts = new Set(results.map((result) => result.publicKey));
  expect(distinctAccounts.size).toBe(5);
  expect(
    results.map((result) => result.sequence),
  ).toEqual(["1", "2", "3", "4", "5"]);

  const loadTestTasks = Array.from({ length: 200 }, (_, index) =>
    pool.withSigner(async (lease) => {
      const signature = await nativeSigner.signPayload(
        lease.account.secret,
        Buffer.from(`bulk-payload-${index}`)
      );

      return {
        publicKey: lease.account.publicKey,
        signature: signature.toString("base64"),
      };
    })
  );

  const loadTestResults = await Promise.all(loadTestTasks);
  expect(loadTestResults.length).toBe(200);
  expect(new Set(loadTestResults.map((result) => result.publicKey)).size).toBe(5);

  await pool.updateBalance(keypairs[0].publicKey(), 10n);
  const snapshot = pool.getSnapshot();
  const deactivated = snapshot.find(
    (account) => account.publicKey === keypairs[0].publicKey()
  );

  expect(deactivated?.active).toBe(false);
  expect(snapshot.filter((account) => account.active).length).toBe(4);
});
