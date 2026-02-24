# Protoss — Rust (curve25519-dalek)

Implementation of the Protoss PAKE protocol using `curve25519-dalek`'s Ristretto255 operations.

## Project Structure

- `/src` — Source code
  - `main.rs` — Demo: runs the full protocol and verifies session keys match
  - `lib.rs` — Library exports
  - `protoss_protocol.rs` — Core protocol (init, rsp_der, der)
  - `ec_operations.rs` — Elliptic curve utilities (hash-to-point, concatenation)
  - `logger.rs` — Logging utility
- `/benchmark` — Performance benchmarking
  - `benchmark.rs` — Measures per-phase timing over many iterations
- `/build` — Output directory (logs, benchmark results)

## Prerequisites

- Rust toolchain (install via [rustup](https://rustup.rs/))

## Building and Running

From the `dalek-rust/` directory:

```bash
# Run the demo
cargo run --bin protoss --release

# Run the benchmark
cargo run --bin benchmark --release
```
