# Protoss — C (libsodium)

Implementation of the Protoss PAKE protocol in pure C using libsodium's Ristretto255 operations.

## Project Structure

- `/src` — Source code
  - `main.c` — Demo: runs the full protocol and verifies session keys match
  - `protoss_protocol.c/.h` — Core protocol (Init, RspDer, Der)
  - `protoss_common.c/.h` — Shared helpers used by protocol variants (hash-to-point, key derivation)
  - `protoss_validated.c/.h` — Variant: validates received Ristretto points before use
  - `protoss_orchestrated.c/.h` — Variant: state orchestrator that manages state by reference
  - `protoss_precomputed.c/.h` — Variant: state orchestrator with precomputed scalar and g^scalar
  - `logger.c/.h` — Logging utility
- `/benchmark` — Performance benchmarking
  - `timing_benchmark.c` — Measures per-phase timing over many iterations
  - `variant_benchmark.c` — Compares all protocol variants side-by-side
- `/external/libsodium-bin` — libsodium headers and prebuilt binaries
- `/lib` — Contains `libsodium.dll` for runtime
- `/build` — Output directory (executables, logs, benchmark results)

## Protocol Variants

The protocol is implemented in several variants for benchmarking and analysis:

- **Baseline** (`protoss_protocol.c`) — Original implementation. State is populated via memcpy inside the Init function.
- **Validated** (`protoss_validated.c`) — Adds `crypto_core_ristretto255_is_valid_point()` checks on received points (I in RspDer, R in Der) before using them in computations.
- **Orchestrated** (`protoss_orchestrated.c`) — Introduces a state orchestrator that creates an empty state via `protoss_orchestrated_state_create()`, then passes it by reference to protocol steps which fill it directly. Includes `protoss_orchestrated_state_destroy()` for secure cleanup.
- **Precomputed** (`protoss_precomputed.c`) — Same orchestrator pattern, but `protoss_precomputed_state_create()` also precomputes the random scalar and g^scalar before the protocol begins. The protocol steps then skip these expensive operations.

## Prerequisites

- Windows 10/11
- C11 compiler (MinGW-w64 gcc recommended)
- libsodium binaries (included in `/external/libsodium-bin`)

## Building and Running

From the `libsodium-c/` directory:

```bash
# Build the demo
gcc -std=c11 -O2 -Iexternal/libsodium-bin/include -Isrc src/main.c src/protoss_protocol.c src/logger.c -Llib -lsodium -o build/main.exe

# Build the benchmark
gcc -std=c11 -O2 -Iexternal/libsodium-bin/include -Isrc benchmark/timing_benchmark.c src/protoss_protocol.c src/logger.c -Llib -lsodium -lm -o build/benchmark.exe

# Build the variant comparison benchmark
gcc -std=c11 -O2 -Iexternal/libsodium-bin/include -Isrc benchmark/variant_benchmark.c src/protoss_protocol.c src/protoss_common.c src/protoss_validated.c src/protoss_orchestrated.c src/protoss_precomputed.c src/logger.c -Llib -lsodium -lm -o build/variant_benchmark.exe

# Run
./build/main.exe

# Run benchmark (default: 10000 iterations, 10 runs)
./build/benchmark.exe

# Run with custom iterations and number of runs
./build/benchmark.exe 5000 5

# Run variant comparison benchmark
./build/variant_benchmark.exe

# Run with custom iterations and number of runs
./build/variant_benchmark.exe 5000 5
```

Make sure `libsodium.dll` (from `/lib`) is in your PATH or next to the executable.
