# Cross-language test vectors

A known-answer test that asserts the C, C++, Rust, and Python implementations compute identical
Protoss values for one fixed input. The protocol uses random scalars, so the ephemeral scalars are
pinned here to make the computation deterministic and comparable across languages.

## Vector

```
pwd = "SharedPassword"
P_i = 0x01 repeated 16 times
P_j = 0x02 repeated 16 times
x, y = the 32-byte little-endian scalars in expected.txt
```

`expected.txt` holds the resulting V, I, R, Z, K as hex. K is SHA-512 of
(Z || I || R || P_i || P_j || V) truncated to 32 bytes, matching the protocol.

## Run

From this directory:

```
PYTHON=../.venv/Scripts/python.exe bash run_all.sh
```

`run_all.sh` builds the four programs, runs them, and checks each output against `expected.txt`.
It links the C and C++ programs against the libsodium in `../libsodium-c`. The Python program loads
`libsodium.dll` from `../python/lib`. Set `PYTHON` to the interpreter that can load it.

Expected output:

```
C: OK
C++: OK
Rust: OK
Python: OK
```
