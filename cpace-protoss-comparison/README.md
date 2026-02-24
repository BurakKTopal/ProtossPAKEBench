# Protoss vs CPace — Performance Comparison

Benchmarks comparing the Protoss and CPace PAKE protocols, implemented in Rust (dalek), C++ (libsodium), and C (libsodium).

## Project Structure

### `/dalek` — Rust comparison
- `/src` — Protoss protocol implementation (same as `dalek-rust/`)
- `/benchmark/pake_comparison.rs` — Side-by-side Protoss vs CPace benchmark

### `/libsodium` — C++ comparison
- `/src` — Protoss protocol implementation (same as `libsodium-cpp/`)
- `/lib` — Contains `crypto_cpace.c/.h` (CPace implementation) and `libsodium.dll`
- `/benchmark/timing_benchmark.cpp` — Side-by-side Protoss vs CPace benchmark

### `/libsodium-c` — C comparison
- `/src` — Protoss protocol implementation (same as `libsodium-c/`)
- `/lib` — Contains `crypto_cpace.c/.h` (CPace implementation) and `libsodium.dll`
- `/benchmark/timing_benchmark.c` — Side-by-side Protoss vs CPace benchmark

## Running

All benchmarks accept optional CLI arguments: `[iterations] [num_runs] [warmup_iterations]`.
Defaults: 50000 iterations, 10 runs, 5000 warmup iterations.

### Rust (dalek)
```bash
cd dalek
cargo run --bin benchmark --release

# Custom: 10000 iterations, 5 runs
cargo run --bin benchmark --release -- 10000 5
```

### C++ (libsodium)
```bash
cd libsodium
g++ -O2 -Iexternal/libsodium-bin/include -Isrc -Ilib benchmark/timing_benchmark.cpp src/protoss_protocol.cpp src/logger.cpp lib/crypto_cpace.c -Llib -lsodium -o build/benchmark.exe
./build/benchmark.exe

# Custom: 10000 iterations, 5 runs
./build/benchmark.exe 10000 5
```

### C (libsodium)
```bash
cd libsodium-c
gcc -std=c11 -O2 -Iexternal/libsodium-bin/include -Isrc -Ilib benchmark/timing_benchmark.c src/protoss_protocol.c src/logger.c lib/crypto_cpace.c -Llib -lsodium -lm -o build/benchmark.exe
./build/benchmark.exe

# Custom: 10000 iterations, 5 runs
./build/benchmark.exe 10000 5
```

Make sure `libsodium.dll` (from `/lib`) is in your PATH or next to the executable.