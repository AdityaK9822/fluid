# Signing Benchmark Report

Generated: 2026-03-25T07:14:08.527Z
Iterations: 5000
Warmup iterations: 500

| Implementation | Avg (ms) | P50 (ms) | P95 (ms) | Ops/sec | Relative to Node |
| --- | ---: | ---: | ---: | ---: | ---: |
| Node stellar-sdk | 0.0857 | 0.0746 | 0.1327 | 11667.88 | 1.00x |
| Rust ed25519-dalek | 0.1655 | 0.1548 | 0.1964 | 6043.69 | 0.52x |

Node min/max: 0.0650 ms / 6.7731 ms
Rust min/max: 0.1321 ms / 5.2847 ms

Methodology:
- Builds one unsigned fee-bump transaction per benchmark run.
- Signs the same transaction repeatedly after clearing signatures to isolate signing latency.
- Verifies parity first to ensure the Rust signer produces the same Ed25519 signature over the Stellar transaction hash as the current Node implementation.
