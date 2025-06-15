# ProtossPAKEBench
Implementation of Protoss in C++ (Libsodium), Rust (Dalek), and Python, including comparisons of CPACE. See 

## Protoss PAKE
For the theoretical details of Protoss, refer to [Protoss paper](./ProtossPaper.pdf) by Di Giandomenico, E., Li, Y. and Schäge, S.

## Structure
- `libsodium-cpp/`: C++ implementation of Protoss in Libsodium. Benchmarking code provided.
- `dalek-rust/`: Rust implementation of Protoss in Dalek. Benchmarking code provided.
- `python/`: Python implementation of Protoss via binding with libsodium. Benchmarking code provided.
- `cpace-protoss-pake-comparison/`: Benchmarks comparing CPACE and Protoss in cpp-Libsodium and Rust-Dalek. Benchmarking code provided. 

## Licensing
- This project is licensed under the [BSD 2-Clause](LICENSE).
- The CPACE library, used in `cpace-protoss-pake-comparison/libsodium/`, is licensed under the BSD 2-Clause License by Frank Denis (2020-2021). See `licenses-used-libraries/LICENSE-CPACE` for details.
- The SODIUM library, used for the C++ implementation of Protoss and the comparison with CPace is licensed under the ISC License by Frank Denis (2013-2025). See `licenses-used-libraries/LICENSE-LIBSODIUM` for details.
