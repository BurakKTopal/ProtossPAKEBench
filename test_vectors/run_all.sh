#!/usr/bin/env bash
# Builds and runs the four known-answer tests and checks each against expected.txt.
# Uses the bundled Windows libsodium when present, otherwise the system libsodium
# (pkg-config) on Linux.
set -u
cd "$(dirname "$0")"

CINC=../libsodium-c/external/libsodium-bin/include
CLIB=../libsodium-c/lib

if [ -f "$CLIB/libsodium.dll" ]; then
    CFLAGS="-I$CINC"
    LIBS="-L$CLIB -lsodium"
    cp -f "$CLIB"/libsodium.dll .
else
    CFLAGS="$(pkg-config --cflags libsodium)"
    LIBS="$(pkg-config --libs libsodium)"
fi

gcc -std=c11 -O2 $CFLAGS kat_c.c $LIBS -o kat_c
g++ -std=c++17 -O2 $CFLAGS kat_cpp.cpp $LIBS -o kat_cpp
( cd rust && cargo build --release --quiet )

expected=$(grep -E '^[VIRZK]=' expected.txt)
fail=0

check() {
    local name="$1"; shift
    local got
    got=$("$@" | grep -E '^[VIRZK]=')
    if [ "$got" = "$expected" ]; then
        echo "$name: OK"
    else
        echo "$name: MISMATCH"
        diff <(echo "$expected") <(echo "$got")
        fail=1
    fi
}

check "C"      ./kat_c
check "C++"    ./kat_cpp
check "Rust"   ./rust/target/release/kat_rust
check "Python" "$PYTHON" kat_python.py

exit $fail
