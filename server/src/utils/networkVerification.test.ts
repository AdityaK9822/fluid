import { describe, expect, it } from "vitest";
import StellarSdk from "@stellar/stellar-sdk";
import { verifyXdrNetwork, KNOWN_NETWORKS } from "../utils/networkVerification";

describe("networkVerification", () => {
  // Helper function to create a test transaction for a specific network
  function createTestTransaction(networkPassphrase: string): string {
    const sourceKeypair = StellarSdk.Keypair.random();
    const sourceAccount = new StellarSdk.Account(sourceKeypair.publicKey(), "0");
    
    const transaction = new StellarSdk.TransactionBuilder(sourceAccount, {
      fee: "100",
      networkPassphrase,
      timebounds: { min: 0, max: 9999999999 },
    })
      .addOperation(
        StellarSdk.Operation.payment({
          destination: StellarSdk.Keypair.random().publicKey(),
          asset: StellarSdk.Asset.native(),
          amount: "10",
        })
      )
      .build();
    
    transaction.sign(sourceKeypair);
    return transaction.toXDR();
  }

  describe("verifyXdrNetwork", () => {
    it("should accept XDR when network matches expected network", () => {
      const testnetXdr = createTestTransaction(KNOWN_NETWORKS.TESTNET);
      
      const result = verifyXdrNetwork(testnetXdr, KNOWN_NETWORKS.TESTNET);
      
      expect(result.valid).toBe(true);
      expect(result.xdrNetwork).toBe(KNOWN_NETWORKS.TESTNET);
      expect(result.expectedNetwork).toBe(KNOWN_NETWORKS.TESTNET);
    });

    it("should reject XDR when network does not match expected network (Mainnet XDR to Testnet server)", () => {
      const mainnetXdr = createTestTransaction(KNOWN_NETWORKS.PUBLIC);
      
      const result = verifyXdrNetwork(mainnetXdr, KNOWN_NETWORKS.TESTNET);
      
      expect(result.valid).toBe(false);
      expect(result.errorMessage).toContain("Network mismatch");
      expect(result.errorMessage).toContain("Mainnet");
      expect(result.errorMessage).toContain("Testnet");
    });

    it("should reject XDR when network does not match expected network (Testnet XDR to Mainnet server)", () => {
      const testnetXdr = createTestTransaction(KNOWN_NETWORKS.TESTNET);
      
      const result = verifyXdrNetwork(testnetXdr, KNOWN_NETWORKS.PUBLIC);
      
      expect(result.valid).toBe(false);
      expect(result.errorMessage).toContain("Network mismatch");
      expect(result.errorMessage).toContain("Testnet");
      expect(result.errorMessage).toContain("Mainnet");
    });

    it("should return error for invalid XDR", () => {
      const result = verifyXdrNetwork("invalid-xdr-string", KNOWN_NETWORKS.TESTNET);
      
      expect(result.valid).toBe(false);
      expect(result.errorMessage).toContain("Invalid XDR");
    });
  });

  describe("KNOWN_NETWORKS", () => {
    it("should have correct Mainnet passphrase", () => {
      expect(KNOWN_NETWORKS.PUBLIC).toBe("Public Global Stellar Network ; September 2015");
    });

    it("should have correct Testnet passphrase", () => {
      expect(KNOWN_NETWORKS.TESTNET).toBe("Test SDF Network ; September 2015");
    });
  });
});