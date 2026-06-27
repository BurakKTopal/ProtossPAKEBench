# Reproducible Protoss benchmark image.
# The same Dockerfile builds an x86-64 image on an x86-64 host and an ARM64
# image on an ARM host, because apt serves the matching-architecture packages.
#
# Build:  docker build -t protoss-bench .
# Run:    docker run --rm -v "$PWD/out:/work/out" protoss-bench
#         (override size: docker run --rm -e ITERS=200 -e RUNS=2 ... protoss-bench)
FROM debian:stable-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        pkg-config \
        libsodium-dev \
        python3 \
        curl \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

# Rust toolchain (stable) for the dalek crates.
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal

WORKDIR /work
COPY . /work

# The Python bindings search python/lib for a file named "libsodium" before
# falling back to the system path. Expose the system library under that exact
# name so the loader finds it, with no Python source change.
RUN mkdir -p /work/python/lib \
    && ln -sf "$(pkg-config --variable=libdir libsodium)/libsodium.so" /work/python/lib/libsodium

ENTRYPOINT ["bash", "run_all_benchmarks.sh"]
