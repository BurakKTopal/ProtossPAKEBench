# Protoss — C (libsodium)

Implementation of the Protoss PAKE protocol in pure C using libsodium's Ristretto255 operations.

## Project Structure

- `/src` — Source code
  - `main.c` — Demo: runs the full protocol and verifies session keys match
  - `protoss_protocol.c/.h` — Core protocol (Init, RspDer, Der)
  - `logger.c/.h` — Logging utility
- `/benchmark` — Performance benchmarking
  - `timing_benchmark.c` — Measures per-phase timing over many iterations
- `/external/libsodium-bin` — libsodium headers and prebuilt binaries
- `/lib` — Contains `libsodium.dll` for runtime
- `/build` — Output directory (executables, logs, benchmark results)

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

# Run
./build/main.exe

# Run benchmark (default: 10000 iterations, 10 runs)
./build/benchmark.exe

# Run with custom iterations and number of runs
./build/benchmark.exe 5000 5
```

Make sure `libsodium.dll` (from `/lib`) is in your PATH or next to the executable.
