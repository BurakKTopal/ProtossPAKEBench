# Protoss vs CPace — Performance Comparison

Benchmarks comparing the Protoss and CPace PAKE protocols, implemented in both Rust (dalek) and C++ (libsodium).

## Project Structure

### `/dalek` — Rust comparison
- `/src` — Protoss protocol implementation (same as `dalek-rust/`)
- `/benchmark/pake_comparison.rs` — Side-by-side Protoss vs CPace benchmark

### `/libsodium` — C++ comparison
- `/src` — Protoss protocol implementation (same as `libsodium-cpp/`)
- `/lib` — Contains `crypto_cpace.c/.h` (CPace implementation) and `libsodium.dll`
- `/benchmark/timing_benchmark.cpp` — Side-by-side Protoss vs CPace benchmark

## Running

### Rust (dalek)
```bash
cd dalek
cargo run --bin benchmark --release
```

### C++ (libsodium)
```bash
cd libsodium
g++ -O2 -Iexternal/libsodium-bin/include -Isrc -Ilib benchmark/timing_benchmark.cpp src/protoss_protocol.cpp src/logger.cpp lib/crypto_cpace.c -Llib -lsodium -o build/benchmark.exe
./build/benchmark.exe
```

Make sure `libsodium.dll` (from `/lib`) is in your PATH or next to the executable.