import StellarSdk from "@stellar/stellar-sdk";

/**
 * Known Stellar network passphrases for identification
 */
export const KNOWN_NETWORKS = {
  PUBLIC: "Public Global Stellar Network ; September 2015",
  TESTNET: "Test SDF Network ; September 2015",
} as const;

/**
 * Result of network verification
 */
export interface NetworkVerificationResult {
  valid: boolean;
  xdrNetwork?: string;
  expectedNetwork?: string;
  errorMessage?: string;
}

/**
 * Extracts a user-friendly network name from a passphrase
 */
function getNetworkName(passphrase: string): string {
  if (passphrase === KNOWN_NETWORKS.PUBLIC) {
    return "Public Network (Mainnet)";
  }
  if (passphrase === KNOWN_NETWORKS.TESTNET) {
    return "Test Network (Testnet)";
  }
  // Return a truncated version of unknown passphrases for logging
  return passphrase.length > 30 ? `${passphrase.substring(0, 30)}...` : passphrase;
}

/**
 * Verifies that an XDR transaction matches the expected network passphrase.
 * 
 * This function attempts to parse the XDR with the expected network passphrase.
 * If that fails, it tries to identify which network the XDR belongs to by
 * attempting to parse with known network passphrases.
 * 
 * @param xdr - The base64 encoded XDR transaction
 * @param expectedNetworkPassphrase - The network passphrase the server is configured for
 * @returns NetworkVerificationResult with success status and details
 */
export function verifyXdrNetwork(
  xdr: string,
  expectedNetworkPassphrase: string
): NetworkVerificationResult {
  // Parse the XDR — fromXDR accepts any passphrase, using it only for hash computation
  let tx: ReturnType<typeof StellarSdk.TransactionBuilder.fromXDR>;
  try {
    tx = StellarSdk.TransactionBuilder.fromXDR(xdr, expectedNetworkPassphrase);
  } catch (e: any) {
    return {
      valid: false,
      expectedNetwork: expectedNetworkPassphrase,
      errorMessage: `Invalid XDR: ${e.message}`,
    };
  }

  // If the transaction carries no signatures there is nothing to verify
  if (!tx.signatures || tx.signatures.length === 0) {
    return { valid: true, xdrNetwork: expectedNetworkPassphrase, expectedNetwork: expectedNetworkPassphrase };
  }

  // The network passphrase is folded into the transaction hash, so a signature
  // created for network A will NOT verify against the hash computed with network B.
  // Use the source account (which must have signed for the common case) to check.
  const sourcePublicKey = tx.source;
  const sig = tx.signatures[0].signature();

  try {
    const keypair = StellarSdk.Keypair.fromPublicKey(sourcePublicKey);

    // Hash computed with the expected passphrase
    if (keypair.verify(tx.hash(), sig)) {
      return { valid: true, xdrNetwork: expectedNetworkPassphrase, expectedNetwork: expectedNetworkPassphrase };
    }

    // Signature invalid for expected network — identify the actual network
    for (const [, passphrase] of Object.entries(KNOWN_NETWORKS)) {
      if (passphrase === expectedNetworkPassphrase) continue;
      const txOther = StellarSdk.TransactionBuilder.fromXDR(xdr, passphrase);
      if (keypair.verify(txOther.hash(), sig)) {
        return {
          valid: false,
          xdrNetwork: passphrase,
          expectedNetwork: expectedNetworkPassphrase,
          errorMessage: `Network mismatch: XDR is for ${getNetworkName(passphrase)} but server is configured for ${getNetworkName(expectedNetworkPassphrase)}`,
        };
      }
    }

    return {
      valid: false,
      expectedNetwork: expectedNetworkPassphrase,
      errorMessage: `Network mismatch: XDR was created for a different network than the server's configured network (${getNetworkName(expectedNetworkPassphrase)})`,
    };
  } catch (e: any) {
    return {
      valid: false,
      expectedNetwork: expectedNetworkPassphrase,
      errorMessage: `Invalid XDR: ${e.message}`,
    };
  }
}

/**
 * Creates an error message for network mismatch that doesn't leak too much
 * internal configuration but is helpful for debugging.
 * 
 * @param xdrNetwork - The network the XDR was created for
 * @param serverNetwork - The network the server is configured for
 * @returns User-friendly error message
 */
export function createNetworkMismatchErrorMessage(
  xdrNetwork: string,
  serverNetwork: string
): string {
  return `Network mismatch: XDR is for ${getNetworkName(xdrNetwork)} but server is configured for ${getNetworkName(serverNetwork)}`;
}