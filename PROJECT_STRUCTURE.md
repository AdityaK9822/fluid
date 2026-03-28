# Project Structure

```text
fluid/
|-- fluid-server/         # Primary Rust production server
|   |-- src/
|   |   |-- main.rs       # Axum server entry point
|   |   |-- horizon.rs    # Redundant Horizon/RPC submission client with failover + health tracking
|   |   |-- stellar.rs    # Fee-bump construction/signing
|   |   |-- state.rs      # Shared runtime state and rate-limit/signer helpers
|   |   |-- config.rs     # Environment mapping
|   |   |-- error.rs      # API error responses
|   |   `-- xdr.rs        # Stellar XDR parsing/logging`
|   |-- tests/
|   |   `-- rust_only_verification.rs
|   `-- Cargo.toml
|-- server/               # Legacy Node.js parity server and migration harness
|   |-- src/
|   |-- scripts/
|   |-- package.json
|   `-- README.md
|-- client/               # TypeScript client SDK
|   |-- src/
|   |-- package.json
|   `-- README.md
|-- MIGRATION_GUIDE.md    # Rust migration and cutover guide
|-- README.md             # Main project documentation
`-- PROJECT_STRUCTURE.md  # This file
```

## Who Submits the Final Transaction?

By default, the client submits the fee-bump transaction after receiving it from the server.

If `submit: true` is set, the server can submit it directly when Horizon URLs are configured.

## Technology Stack

- Server: Rust + Axum
- Legacy parity server: Node.js + TypeScript + Express
- Client: Node.js + TypeScript
- Stellar tooling: `stellar-xdr`, `ed25519-dalek`, `@stellar/stellar-sdk`
