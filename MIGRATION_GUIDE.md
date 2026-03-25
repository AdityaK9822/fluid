# Rust Migration Guide

This repository now treats `fluid-server/` as the primary production server. The legacy Node.js server in `server/` remains available as a parity reference and rollback path during migration.

## What Moved

- Express routing moved to Axum.
- API key auth and rate limiting are enforced by the Rust server.
- Fee-bump construction and signing now run fully in Rust.
- The dashboard is bundled into the Rust binary and served from `/` and `/dashboard`.
- Test helper routes are available in Rust.

## Environment Variable Mapping

The Rust server uses the same environment variables as the Node.js server:

```bash
FLUID_FEE_PAYER_SECRET
FLUID_BASE_FEE
FLUID_FEE_MULTIPLIER
STELLAR_NETWORK_PASSPHRASE
STELLAR_HORIZON_URL
STELLAR_HORIZON_URLS
FLUID_HORIZON_SELECTION
FLUID_RATE_LIMIT_WINDOW_MS
FLUID_RATE_LIMIT_MAX
FLUID_ALLOWED_ORIGINS
PORT
```

## Rust-First Runbook

Build and run:

```bash
cd fluid-server
cargo build
cargo run
```

Verify Rust-only serving:

```bash
cargo test rust_server_handles_static_and_api_without_node --test rust_only_verification -- --nocapture
```

Run Node-vs-Rust parity checks:

```bash
cd ../server
npm install
npm run parity:rust
```

## Cutover Notes

- Point production traffic at the Rust binary first.
- Keep the Node server available only as rollback during rollout.
- Run the parity harness before each Rust release candidate.
- Remove Node from the production deployment only after the Rust-only verification passes in the target environment.
