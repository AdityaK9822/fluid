# Fluid Client

TypeScript client library for interacting with Fluid servers.

## Installation

```bash
npm install
```

## Usage

```typescript
import { FluidClient } from "fluid-client";
import StellarSdk from "@stellar/stellar-sdk";

const client = new FluidClient({
  serverUrl: "http://localhost:3000",
  networkPassphrase: StellarSdk.Networks.TESTNET,
  horizonUrl: "https://horizon-testnet.stellar.org",
  sorobanRpcUrl: "https://soroban-testnet.stellar.org",
});

const transaction = new StellarSdk.TransactionBuilder(account, {
  fee: StellarSdk.BASE_FEE,
  networkPassphrase: StellarSdk.Networks.TESTNET,
})
  .addOperation(/* your operation */)
  .build();

transaction.sign(keypair);

const result = await client.requestFeeBump(transaction, false);
const submitResult = await client.submitFeeBumpTransaction(result.xdr);
```

## Soroban SAC helper

```typescript
import StellarSdk from "@stellar/stellar-sdk";
import { FluidClient } from "./src";

const client = new FluidClient({
  serverUrl: "http://localhost:3000",
  networkPassphrase: StellarSdk.Networks.TESTNET,
  sorobanRpcUrl: "https://soroban-testnet.stellar.org",
});

const prepared = await client.buildSACTransferTx({
  source: "G...SOURCE",
  destination: "G...DESTINATION",
  asset: "native",
  amount: "1000000",
});

console.log(prepared.toXDR());
```

Supported `asset` inputs:

- `"native"` or `"xlm"` for Native XLM
- `"CODE:ISSUER"` for issued assets
- `new StellarSdk.Asset(code, issuer)`
- `{ code, issuer }`

Soroban-specific options:

- `sorobanRpcUrl`: required so the SDK can simulate and prepare the invoke-host-function transaction
- `amount`: must be provided in integer base units expected by the SAC
- `timeoutInSeconds`: optional transaction timeout, default `180`
- `fee`: optional base fee before Soroban resource fees are added during preparation
- `sourceAccount`: optional preloaded source account if you want to avoid an extra RPC call

To print a successfully generated SAC transfer XDR on testnet:

```bash
npm run demo:sac-transfer-xdr
```

## API

### `FluidClient`

#### Constructor

```typescript
new FluidClient(config: {
  serverUrl: string;
  networkPassphrase: string;
  horizonUrl?: string;
  sorobanRpcUrl?: string;
  enableTelemetry?: boolean; // Enable anonymous telemetry (default: false)
  telemetryEndpoint?: string; // Custom telemetry endpoint (default: 'https://telemetry.fluid.dev/ping')
})
```

#### Methods

- `requestFeeBump(transactionOrXdr: string | { toXDR(): string }, submit?: boolean)` - Request a fee-bump using either signed XDR or a transaction object
- `submitFeeBumpTransaction(feeBumpXdr: string)` - Submit a fee-bump transaction to Horizon
- `buildAndRequestFeeBump(transaction: Transaction, submit?: boolean)` - Build, sign, and request fee-bump
- `buildSACTransferTx(options)` - Build and prepare a Stellar Asset Contract transfer transaction ready for signing and fee bumping

### `useFeeBump`

```typescript
const { requestFeeBump, isLoading, error, result } = useFeeBump(client);
```

- `requestFeeBump(transactionOrXdr, submit?)` accepts either a signed XDR string or an object with `toXDR()`
- `isLoading` is `true` while the request is in flight
- `error` contains the last thrown error, if any
- `result` contains the latest successful fee-bump response

## Anonymous Usage Telemetry

The Fluid SDK includes an optional, anonymous telemetry system to help maintainers understand SDK usage patterns.

**Telemetry is disabled by default (opt-in).**

### What is Collected?

When enabled, the SDK sends a single daily ping with:

- `sdk_version`: The installed package version
- `domain`: `window.location.hostname` (no path, no query params)
- `timestamp`: UTC date (day-level precision only)

**No personal data, transaction data, or wallet addresses are collected.**

### How to Enable Telemetry

```typescript
const client = new FluidClient({
  serverUrl: "http://localhost:3000",
  networkPassphrase: StellarSdk.Networks.TESTNET,
  enableTelemetry: true, // Enable anonymous telemetry
});
```

### How to Disable Telemetry

Telemetry is disabled by default. To explicitly disable it:

```typescript
const client = new FluidClient({
  serverUrl: "http://localhost:3000",
  networkPassphrase: StellarSdk.Networks.TESTNET,
  enableTelemetry: false, // Explicitly disable (this is the default)
});
```

For more details, see [TELEMETRY.md](TELEMETRY.md).

## Development

```bash
npm run build
npm run dev
npm run demo:sac-transfer-xdr
```
