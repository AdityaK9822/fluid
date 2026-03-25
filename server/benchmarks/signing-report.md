# Signing Benchmark Report

Generated: 2026-03-25T17:12:45.461Z
Iterations: 5000
Warmup iterations: 500

| Implementation | Avg (ms) | P50 (ms) | P95 (ms) | Ops/sec | Relative to Node |
| --- | ---: | ---: | ---: | ---: | ---: |
| Node stellar-sdk | 0.0868 | 0.0748 | 0.1418 | 11526.93 | 1.00x |
| Rust ed25519-dalek | 0.1515 | 0.1520 | 0.1724 | 6602.16 | 0.57x |

Node min/max: 0.0646 ms / 3.9932 ms
Rust min/max: 0.1234 ms / 0.5097 ms

Methodology:
- Builds one unsigned fee-bump transaction per benchmark run.
- Signs the same transaction repeatedly after clearing signatures to isolate signing latency.
- Verifies parity first to ensure the Rust signer produces the same Ed25519 signature over the Stellar transaction hash as the current Node implementation.
