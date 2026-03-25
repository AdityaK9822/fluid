# Fluid - Stellar Fee Sponsorship Service

Fluid enables gasless Stellar transactions by abstracting network fees. Users sign transactions locally, and Fluid wraps them in fee-bump transactions so applications can sponsor XLM fees while users transact in the asset they actually want to use.

## Status

`fluid-server/` is now the primary production backend.

`server/` remains in the repository as a Node.js parity server and migration harness while the Rust rollout completes.

## Quick Start

### Prerequisites

- Rust toolchain with `cargo`
- Node.js 18+ and npm for parity checks and the TypeScript client
- A Stellar account with XLM for fee payments

### Start the Rust Server

```bash
git clone <repository-url>
cd fluid/fluid-server
cargo build
cargo run
```

The Rust server listens on `http://localhost:3000` by default.

### Required Environment

The Rust server uses the same environment variable names as the legacy Node server:

```bash
FLUID_FEE_PAYER_SECRET=SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
FLUID_BASE_FEE=100
FLUID_FEE_MULTIPLIER=2.0
STELLAR_NETWORK_PASSPHRASE=Test SDF Network ; September 2015
STELLAR_HORIZON_URL=https://horizon-testnet.stellar.org
STELLAR_HORIZON_URLS=
FLUID_HORIZON_SELECTION=priority
FLUID_RATE_LIMIT_WINDOW_MS=60000
FLUID_RATE_LIMIT_MAX=5
FLUID_ALLOWED_ORIGINS=
PORT=3000
```

## API

The Rust server handles:

- `GET /`
- `GET /dashboard`
- `GET /health`
- `POST /fee-bump`
- `POST /test/add-transaction`
- `GET /test/transactions`

## Verification

Rust-only verification:

```bash
cd fluid-server
cargo test rust_server_handles_static_and_api_without_node --test rust_only_verification -- --nocapture
```

Node-vs-Rust parity verification:

```bash
cd ../server
npm install
npm run parity:rust
```

## Client

The TypeScript client remains in `client/` and can continue targeting the same HTTP API.

## Migration

See `MIGRATION_GUIDE.md` for the Rust cutover path, environment mapping, and rollout guidance.
