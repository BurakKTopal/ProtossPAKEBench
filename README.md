# ProtossPAKEBench
Implementation of Protoss in C (libsodium), C++ (libsodium), Rust (Dalek), and Python, including comparisons with CPace.

## Protoss PAKE
For the theoretical details of Protoss, refer to [Protoss paper](./ProtossPaper.pdf) by Di Giandomenico, E., Li, Y. and Schäge, S.

## Structure
- `libsodium-c/`: C implementation of Protoss using libsodium's Ristretto255 operations. Benchmarking code provided.
- `libsodium-cpp/`: C++ implementation of Protoss using libsodium. Benchmarking code provided.
- `dalek-rust/`: Rust implementation of Protoss using curve25519-dalek. Benchmarking code provided.
- `python/`: Python implementation of Protoss via ctypes bindings with libsodium. Benchmarking code provided.
- `cpace-protoss-comparison/`: Benchmarks comparing CPace and Protoss in C (libsodium), C++ (libsodium), and Rust (Dalek). Benchmarking code provided.

## Licensing
- This project is licensed under the [BSD 2-Clause](LICENSE).
- The CPACE library, used in `cpace-protoss-comparison/`, is licensed under the BSD 2-Clause License by Frank Denis (2020-2021). See `licenses-used-libraries/LICENSE-CPACE` for details.
- The SODIUM library, used for the C and C++ implementations of Protoss and the comparison with CPace, is licensed under the ISC License by Frank Denis (2013-2025). See `licenses-used-libraries/LICENSE-LIBSODIUM` for details.
