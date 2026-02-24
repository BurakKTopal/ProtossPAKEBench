# Protoss — C++ (libsodium)

Implementation of the Protoss PAKE protocol using libsodium's Ristretto255 operations.

## Project Structure

- `/src` — Source code
  - `main.cpp` — Demo: runs the full protocol and verifies session keys match
  - `protoss_protocol.cpp/.hpp` — Core protocol (Init, RspDer, Der)
  - `logger.cpp/.hpp` — Logging utility
- `/benchmark` — Performance benchmarking
  - `timing_benchmark.cpp` — Measures per-phase timing over many iterations
- `/external/libsodium-bin` — libsodium headers and prebuilt binaries
- `/lib` — Contains `libsodium.dll` for runtime
- `/build` — Output directory (executables, logs, benchmark results)

## Prerequisites

- Windows 10/11
- C++17 compiler (MinGW-w64 g++ recommended)
- libsodium binaries (included in `/external/libsodium-bin`)

## Building and Running

From the `libsodium-cpp/` directory:

```bash
# Build the demo
g++ -O2 -Iexternal/libsodium-bin/include -Isrc src/main.cpp src/protoss_protocol.cpp src/logger.cpp -Llib -lsodium -o build/main.exe

# Build the benchmark
g++ -O2 -Iexternal/libsodium-bin/include -Isrc benchmark/timing_benchmark.cpp src/protoss_protocol.cpp src/logger.cpp -Llib -lsodium -o build/benchmark.exe

# Run
./build/main.exe
# Run (default: 10000 iterations, 10 runs)
./build/benchmark.exe

# Run with custom iterations and number of runs
./build/benchmark.exe 5000 5
```

Make sure `libsodium.dll` (from `/lib`) is in your PATH or next to the executable.
