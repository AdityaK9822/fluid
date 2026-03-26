## Title
feat: implement network isolation for transactions

## Description

This PR adds network isolation functionality to ensure that incoming XDR transactions are validated against the server's configured Stellar network passphrase. This prevents users from accidentally submitting Mainnet transactions to a Testnet server (or vice versa), which could lead to confusion and unnecessary fee expenditure on the wrong ledger.

### Changes Made

1. **Network Verification Utility** (`server/src/utils/networkVerification.ts`)
   - Created `verifyXdrNetwork()` function that validates XDR transactions against the server's configured network
   - Uses `StellarSdk.TransactionBuilder.fromXDR` with different passphrases to identify the network
   - Returns clear error messages: "Network mismatch: XDR is for [Network] but server is configured for [Network]"

2. **Integration in feeBumpHandler** (`server/src/handlers/feeBump.ts`)
   - Added network verification check early in the handler (after XDR parsing)
   - Rejects mismatched transactions with 400 Bad Request and `NETWORK_MISMATCH` error code

3. **Error Code Addition** (`server/src/errors/AppError.ts`)
   - Added `NETWORK_MISMATCH` to the `ErrorCode` type

4. **Tests**
   - Unit tests for network verification utility
   - Integration tests verifying:
     - Mainnet XDR rejected by Testnet server ✓
     - Testnet XDR rejected by Mainnet server ✓
     - Testnet XDR accepted by Testnet server ✓

### Additional Fix
- Fixed a pre-existing bug by adding missing `await` to `checkTenantDailyQuota()` call

### Acceptance Criteria Met
- ✓ Server identifies the network of the incoming XDR
- ✓ Rejects the request if the XDR network does not match STELLAR_NETWORK_PASSPHRASE
- ✓ Returns 400 Bad Request with descriptive error message
- ✓ Network verification utility created
- ✓ Integration in feeBumpHandler completed
- ✓ Tests verifying Mainnet XDR rejection by Testnet server

### Example Error Response
```json
{
  "error": "Network mismatch: XDR is for Public Network (Mainnet) but server is configured for Test Network (Testnet)",
  "code": "NETWORK_MISMATCH",
  "statusCode": 400
}