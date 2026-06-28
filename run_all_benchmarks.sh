#!/usr/bin/env bash
# Build every implementation against the system libsodium and run the full
# benchmark suite. Intended to run inside the Docker image on Linux, on both
# x86-64 and ARM. Results and a machine description are written to an
# architecture-tagged directory under OUT_DIR.
#
# Config (override via env):
#   ITERS, RUNS   benchmark size (default 100000 x 10)
#   OUT_DIR       output root (default ./out)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
ITERS="${ITERS:-100000}"
RUNS="${RUNS:-10}"
OUT_DIR="${OUT_DIR:-$ROOT/out}"

ARCH="$(uname -m)"
STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
DEST="$OUT_DIR/${ARCH}_${STAMP}"
mkdir -p "$DEST"

# Mirror all stdout and stderr to a live log inside the result folder, so
# progress can be followed from any shell with `tail -f .../run.log` without
# attaching to the running session.
exec > >(tee -a "$DEST/run.log") 2>&1

SODIUM_CFLAGS="$(pkg-config --cflags libsodium)"
SODIUM_LIBS="$(pkg-config --libs libsodium)"

# _POSIX_C_SOURCE exposes clock_gettime / CLOCK_MONOTONIC from <time.h> on Linux.
C_FLAGS="-std=c11 -O2 -D_POSIX_C_SOURCE=199309L"
CXX_FLAGS="-std=c++17 -O2"

# Total number of stage() markers below, kept in sync so the [i/N] counter is
# meaningful. Update if stages are added or removed.
TOTAL_STAGES=15
STAGE_NUM=0
log() { echo "[run_all] $(date +%H:%M:%S) $*"; }
stage() {
    STAGE_NUM=$((STAGE_NUM + 1))
    echo "[run_all] $(date +%H:%M:%S) [${STAGE_NUM}/${TOTAL_STAGES}] $*"
}
# Run one benchmark with a clear START/DONE banner, so a long silent stage is
# announced before it begins and confirmed when it ends.
run_step() {
    local desc="$1"; shift
    echo "[run_all] $(date +%H:%M:%S)   -> START  $desc"
    "$@"
    echo "[run_all] $(date +%H:%M:%S)   -> DONE   $desc"
}

# Record the environment so the numbers are reproducible.
write_machine_info() {
    {
        echo "date: $STAMP"
        echo "arch: $ARCH"
        echo "uname: $(uname -a)"
        echo "containerized: yes"
        echo
        echo "[cpu]"
        if [ -r /proc/cpuinfo ]; then
            grep -m1 "model name" /proc/cpuinfo || grep -m1 "Model" /proc/cpuinfo || true
            echo "cores: $(nproc)"
        fi
        echo
        echo "[memory]"
        grep -m1 "MemTotal" /proc/meminfo 2>/dev/null || true
        echo
        echo "[governor]"
        for g in /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor; do
            [ -r "$g" ] && echo "scaling_governor: $(cat "$g")" || echo "scaling_governor: unavailable"
        done
        echo
        echo "[versions]"
        echo "gcc: $(gcc --version | head -1)"
        echo "g++: $(g++ --version | head -1)"
        echo "rustc: $(rustc --version)"
        echo "python: $(python3 --version 2>&1)"
        echo "libsodium: $(pkg-config --modversion libsodium)"
        echo "config: ${ITERS} iterations x ${RUNS} runs"
    } > "$DEST/machine.txt"
}

# Collect every result file a target produced into the destination, tagged so
# files from different targets do not collide.
collect_results() {
    local label="$1" dir="$2"
    if [ -d "$dir" ]; then
        find "$dir" -type f -name '*.txt' | while read -r f; do
            cp "$f" "$DEST/${label}__$(basename "$f")"
        done
    fi
}

log "Run started. Config: ${ITERS} iterations x ${RUNS} runs. Output: $DEST"
log "Follow progress from any shell with: tail -f $DEST/run.log"

# --- Correctness gate: all four languages must agree on the test vectors ---
stage "Cross-language known-answer test"
( cd "$ROOT/test_vectors" && PYTHON=python3 bash run_all.sh ) | tee "$DEST/kat.log"

# --- C ---
stage "Building C"
C="$ROOT/libsodium-c"
mkdir -p "$C/build"
gcc $C_FLAGS $SODIUM_CFLAGS -I"$C/src" \
    "$C/benchmark/timing_benchmark.c" "$C/src/protoss_protocol.c" "$C/src/logger.c" \
    $SODIUM_LIBS -lm -o "$C/build/benchmark"
gcc $C_FLAGS $SODIUM_CFLAGS -I"$C/src" \
    "$C/benchmark/variant_benchmark.c" "$C/src/protoss_protocol.c" "$C/src/protoss_common.c" \
    "$C/src/protoss_validated.c" "$C/src/protoss_orchestrated.c" "$C/src/protoss_precomputed.c" "$C/src/logger.c" \
    $SODIUM_LIBS -lm -o "$C/build/variant_benchmark"
stage "Running C per-phase and variants"
run_step "C per-phase"  bash -c "cd '$C' && ./build/benchmark '$ITERS' '$RUNS'"
collect_results "c_perphase_variants" "$C/benchmark_results"
run_step "C variants"   bash -c "cd '$C' && ./build/variant_benchmark '$ITERS' '$RUNS'"
collect_results "c_perphase_variants" "$C/benchmark_results"

# --- C++ ---
stage "Building C++"
CPP="$ROOT/libsodium-cpp"
mkdir -p "$CPP/build"
g++ $CXX_FLAGS $SODIUM_CFLAGS -I"$CPP/src" \
    "$CPP/benchmark/timing_benchmark.cpp" "$CPP/src/protoss_protocol.cpp" "$CPP/src/logger.cpp" \
    $SODIUM_LIBS -o "$CPP/build/benchmark"
g++ $CXX_FLAGS $SODIUM_CFLAGS -I"$CPP/src" \
    "$CPP/benchmark/variant_benchmark.cpp" "$CPP/src/protoss_protocol.cpp" \
    "$CPP/src/protoss_validated.cpp" "$CPP/src/protoss_orchestrated.cpp" "$CPP/src/protoss_precomputed.cpp" "$CPP/src/logger.cpp" \
    $SODIUM_LIBS -o "$CPP/build/variant_benchmark"
stage "Running C++ per-phase and variants"
run_step "C++ per-phase"  bash -c "cd '$CPP' && ./build/benchmark '$ITERS' '$RUNS'"
collect_results "cpp_perphase_variants" "$CPP/benchmark_results"
run_step "C++ variants"   bash -c "cd '$CPP' && ./build/variant_benchmark '$ITERS' '$RUNS'"
collect_results "cpp_perphase_variants" "$CPP/benchmark_results"

# --- Rust (main impl: per-phase + variants) ---
stage "Building Rust main impl"
( cd "$ROOT/dalek-rust" && cargo build --release )
stage "Running Rust per-phase and variants"
run_step "Rust per-phase"  bash -c "cd '$ROOT/dalek-rust' && ./target/release/benchmark '$ITERS' '$RUNS'"
collect_results "rust_perphase_variants" "$ROOT/dalek-rust/build/benchmark_results"
run_step "Rust variants"   bash -c "cd '$ROOT/dalek-rust' && ./target/release/variant_benchmark '$ITERS' '$RUNS'"
collect_results "rust_perphase_variants" "$ROOT/dalek-rust/build/benchmark_results"

# --- Python (per-phase + variants) ---
# python3 -u keeps stdout unbuffered so per-run progress appears live in the log.
stage "Running Python per-phase and variants"
run_step "Python per-phase"  bash -c "cd '$ROOT/python' && PYTHONPATH=src python3 -u benchmark/timing_benchmark.py '$ITERS' '$RUNS'"
collect_results "python_perphase_variants" "$ROOT/python/build/benchmark_results"
run_step "Python variants"   bash -c "cd '$ROOT/python' && PYTHONPATH=src python3 -u benchmark/variant_benchmark.py '$ITERS' '$RUNS'"
collect_results "python_perphase_variants" "$ROOT/python/build/benchmark_results"

# --- Protoss vs CPace comparison (C, C++, Rust) ---
stage "Building C comparison"
CC="$ROOT/cpace-protoss-comparison/libsodium-c"
mkdir -p "$CC/build"
gcc $C_FLAGS $SODIUM_CFLAGS -I"$CC/src" -I"$CC/lib" \
    "$CC/benchmark/timing_benchmark.c" "$CC/src/protoss_protocol.c" "$CC/src/protoss_common.c" \
    "$CC/src/protoss_precomputed.c" "$CC/src/logger.c" "$CC/lib/crypto_cpace.c" \
    $SODIUM_LIBS -lm -o "$CC/build/benchmark"
stage "Running C comparison"
run_step "C comparison"  bash -c "cd '$CC' && ./build/benchmark '$ITERS' '$RUNS'"
collect_results "c_comparison" "$CC/benchmark_results"

stage "Building C++ comparison"
CCPP="$ROOT/cpace-protoss-comparison/libsodium-cpp"
mkdir -p "$CCPP/build"
g++ $CXX_FLAGS $SODIUM_CFLAGS -I"$CCPP/src" -I"$CCPP/lib" \
    "$CCPP/benchmark/timing_benchmark.cpp" "$CCPP/src/protoss_protocol.cpp" \
    "$CCPP/src/protoss_precomputed.cpp" "$CCPP/src/logger.cpp" "$CCPP/lib/crypto_cpace.c" \
    $SODIUM_LIBS -o "$CCPP/build/benchmark"
stage "Running C++ comparison"
run_step "C++ comparison"  bash -c "cd '$CCPP' && ./build/benchmark '$ITERS' '$RUNS'"
collect_results "cpp_comparison" "$CCPP/benchmark_results"

stage "Building Rust comparison"
( cd "$ROOT/cpace-protoss-comparison/dalek" && cargo build --release )
stage "Running Rust comparison"
run_step "Rust comparison"  bash -c "cd '$ROOT/cpace-protoss-comparison/dalek' && ./target/release/benchmark '$ITERS' '$RUNS'"
collect_results "rust_comparison" "$ROOT/cpace-protoss-comparison/dalek/build/benchmark_results"

write_machine_info

log "Done. Results in: $DEST"
ls -1 "$DEST"
