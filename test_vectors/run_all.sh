#!/usr/bin/env bash
# Builds and runs the four known-answer tests and checks each against expected.txt.
set -u
cd "$(dirname "$0")"

CINC=../libsodium-c/external/libsodium-bin/include
CLIB=../libsodium-c/lib

gcc -std=c11 -O2 -I"$CINC" kat_c.c -L"$CLIB" -lsodium -o kat_c.exe
g++ -std=c++17 -O2 -I"$CINC" kat_cpp.cpp -L"$CLIB" -lsodium -o kat_cpp.exe
cp -f "$CLIB"/libsodium.dll .
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

check "C"      ./kat_c.exe
check "C++"    ./kat_cpp.exe
check "Rust"   ./rust/target/release/kat_rust.exe
check "Python" "$PYTHON" kat_python.py

exit $fail
