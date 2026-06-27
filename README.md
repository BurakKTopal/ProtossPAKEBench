# ProtossPAKEBench

Implementations and benchmarks of the Protoss balanced PAKE protocol in C, C++, Rust, and Python,
with a like-for-like comparison against the standardized PAKE CPace.

All four implementations operate over the Ristretto255 prime-order group: C, C++, and Python through
libsodium, Rust through curve25519-dalek. The implementations are cross-validated against a shared
set of test vectors so that every language computes byte-identical protocol values for the same
inputs.

For the protocol and its security analysis, see the [Protoss paper](./ProtossPaper.pdf) by
Di Giandomenico, E., Li, Y., and Schäge, S.

## Protocol

Protoss establishes a shared session key from a common password in two messages. Each party blinds
an ephemeral Diffie-Hellman share with the hashed password:

    Init    (initiator): X = g^x, V = H(pwd), send I = X * V
    RspDer  (responder): Y = g^y, R = Y * V, Z = (I / V)^y, K = H'(Z, I, R, P_i, P_j, V)
    Der     (initiator): Z = (R / V)^x, K = H'(Z, I, R, P_i, P_j, V)

Both parties derive the same key K = H'(g^xy, I, R, P_i, P_j, V). H is a hash-to-point map and H' is
SHA-512 truncated to 32 bytes.

## Variants

Each language implements the baseline protocol and three variants:

- **baseline**: the protocol as described above.
- **validated**: adds a Ristretto point validity check on every received point (I in RspDer, R in
  Der) before it is used.
- **orchestrated**: a state object is created up front and passed to each step by reference, which
  fills it in place; the secret scalar is wiped on cleanup. This is a state-management refactor with
  no change to the cryptographic work.
- **precomputed**: the ephemeral scalar and g^scalar are computed once during state setup, before
  the protocol runs, removing the fixed-base exponentiation from the online path.

CPace, by contrast, derives its generator from the password and a fresh per-session identifier, so
it has no fixed point to precompute. The comparison benchmark reports precomputed Protoss both with
and without its setup cost, so the online-latency advantage and the unchanged total work are both
visible.

## Structure

- `libsodium-c/`, `libsodium-cpp/`, `dalek-rust/`, `python/`: the four implementations, each with a
  per-phase timing benchmark and a four-variant comparison benchmark under `benchmark/`.
- `cpace-protoss-comparison/`: Protoss-vs-CPace benchmarks in C, C++, and Rust. Each runs baseline
  Protoss, precomputed Protoss, and CPace in one rotated loop.
- `test_vectors/`: a known-answer test that checks all four languages produce identical
  V, I, R, Z, K for a fixed input. See `test_vectors/README.md`.
- `Dockerfile`, `run_all_benchmarks.sh`: the reproducible benchmark pipeline.
- `licenses-used-libraries/`: licenses of the bundled third-party libraries.

## Running the full suite (recommended)

The Docker image builds every implementation against the system libsodium and runs the whole suite
(test vectors, per-phase timings, variant comparisons, and the Protoss-vs-CPace comparison). The
same Dockerfile produces an x86-64 image on an x86-64 host and an ARM64 image on an ARM host, so the
benchmark can be repeated across architectures with the same commands.

    docker build -t protoss-bench .

    # smoke test (seconds): confirms the pipeline works end to end
    docker run --rm -e ITERS=200 -e RUNS=2 -v "$PWD/out:/work/out" protoss-bench

    # full campaign (default 100000 iterations x 50 runs)
    docker run --rm -v "$PWD/out:/work/out" protoss-bench

Results are written to `out/<arch>_<timestamp>/`, one file per benchmark, alongside a `machine.txt`
recording the CPU, memory, governor state, and tool versions.

On Windows running from MSYS or Git Bash, replace `$PWD` with `$(pwd -W)` so Docker Desktop receives
a Windows-style path for the bind mount. On Linux, including cloud ARM instances, use `$PWD` as
shown.

## Benchmark methodology

- **Iteration-level rotation.** Benchmarks that compare several implementations (the variant
  comparison and the Protoss-vs-CPace comparison) run one round of each per iteration, so a transient
  CPU-load spike is spread evenly rather than concentrated in one implementation's block.
- **Warmup and repeated runs.** Each benchmark warms up, then runs N times; results are reported as
  the mean and sample standard deviation across runs.
- **Key-agreement checks.** Every iteration verifies that both parties derived the same key (for
  both Protoss and CPace in the comparison). A mismatch aborts the run, so timing numbers can only
  come from correct executions. The check runs outside the timed region and does not affect the
  reported numbers.
- **Fixed inputs.** A fixed password and fixed 16-byte party identifiers are used, matching across
  protocols and languages.

## Building a single implementation

Each implementation can also be built and run on its own. On Linux, link against the system
libsodium (`pkg-config --cflags --libs libsodium`); the bundled `external/libsodium-bin` and `lib`
directories hold Windows binaries for building on Windows. For example, the C variant comparison on
Linux:

    cd libsodium-c
    gcc -std=c11 -O2 -D_POSIX_C_SOURCE=199309L $(pkg-config --cflags libsodium) -Isrc \
        benchmark/variant_benchmark.c src/protoss_protocol.c src/protoss_common.c \
        src/protoss_validated.c src/protoss_orchestrated.c src/protoss_precomputed.c src/logger.c \
        $(pkg-config --libs libsodium) -lm -o build/variant_benchmark
    ./build/variant_benchmark 10000 10

The Rust crates build with `cargo build --release`; the Python benchmarks run with `PYTHONPATH=src
python3 benchmark/<name>.py`.

## Licensing

- This project is licensed under the [BSD 2-Clause](LICENSE).
- CPace, used in `cpace-protoss-comparison/`, is licensed under the BSD 2-Clause License by
  Frank Denis (2020-2021). See `licenses-used-libraries/LICENSE-CPACE`.
- libsodium, used by the C, C++, and Python implementations, is licensed under the ISC License by
  Frank Denis (2013-2025). See `licenses-used-libraries/LICENSE-LIBSODIUM`.
