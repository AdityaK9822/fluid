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
  // First, try to parse with the expected network passphrase
  try {
    StellarSdk.TransactionBuilder.fromXDR(xdr, expectedNetworkPassphrase);
    // If parsing succeeds, the XDR matches the expected network
    return {
      valid: true,
      xdrNetwork: expectedNetworkPassphrase,
      expectedNetwork: expectedNetworkPassphrase,
    };
  } catch (expectedError: any) {
    // Check if it's a network mismatch error (TransactionBuilder will throw
    // an error with a message indicating network mismatch)
    const errorMessage = expectedError.message || "";
    
    // If the error is about network mismatch, try to identify the actual network
    if (errorMessage.includes("network") || errorMessage.includes("passphrase")) {
      // Try to identify which network the XDR belongs to
      for (const [networkName, networkPassphrase] of Object.entries(KNOWN_NETWORKS)) {
        try {
          StellarSdk.TransactionBuilder.fromXDR(xdr, networkPassphrase);
          // Found the matching network
          const xdrNetwork = networkPassphrase;
          return {
            valid: false,
            xdrNetwork,
            expectedNetwork: expectedNetworkPassphrase,
            errorMessage: `Network mismatch: XDR is for ${getNetworkName(xdrNetwork)} but server is configured for ${getNetworkName(expectedNetworkPassphrase)}`,
          };
        } catch {
          // This network doesn't match, try the next one
          continue;
        }
      }
      
      // Could not identify the network, but we know it doesn't match
      return {
        valid: false,
        expectedNetwork: expectedNetworkPassphrase,
        errorMessage: `Network mismatch: XDR was created for a different network than the server's configured network (${getNetworkName(expectedNetworkPassphrase)})`,
      };
    }
    
    // Some other parsing error (not network-related)
    return {
      valid: false,
      expectedNetwork: expectedNetworkPassphrase,
      errorMessage: `Invalid XDR: ${errorMessage}`,
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