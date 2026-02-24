# Protoss — Python (libsodium via ctypes)

Implementation of the Protoss PAKE protocol using ctypes bindings to libsodium.

## Project Structure

- `/src` — Source code
  - `main.py` — Demo: runs the full protocol and verifies session keys match
  - `protoss_protocol.py` — Core protocol (Init, RspDer, Der)
  - `sodium_bindings.py` — ctypes bindings to libsodium
  - `logger.py` — Logging utility
  - `__init__.py` — Package init (initializes libsodium)
- `/benchmark` — Performance benchmarking
  - `timing_benchmark.py` — Measures per-phase timing over many iterations
- `/lib` — Contains `libsodium.dll` for runtime

## Prerequisites

- Python 3.8+
- No pip dependencies required (uses only standard library)
- `libsodium.dll` (included in `/lib`)

## Running

From the `python/` directory:

```bash
# Run the demo
python src/main.py

# Run the benchmark
python benchmark/timing_benchmark.py
```
