import sys
import os
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python", "src"))
import sodium_bindings as sodium

PWD = b"SharedPassword"
P_I = bytes([0x01] * 16)
P_J = bytes([0x02] * 16)
X = bytes.fromhex("a1b2c3d4e5f6071829304152637485960a1b2c3d4e5f60718293a4b5c6d70010")
Y = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d20010")


def main():
    V = sodium.crypto_core_ristretto255_from_hash(hashlib.sha512(PWD).digest())
    X_point = sodium.crypto_scalarmult_ristretto255_base(X)
    Y_point = sodium.crypto_scalarmult_ristretto255_base(Y)
    I = sodium.crypto_core_ristretto255_add(X_point, V)
    R = sodium.crypto_core_ristretto255_add(Y_point, V)
    Z = sodium.crypto_scalarmult_ristretto255(Y, sodium.crypto_core_ristretto255_sub(I, V))
    K = hashlib.sha512(Z + I + R + P_I + P_J + V).digest()[:32]
    for name, val in [("V", V), ("I", I), ("R", R), ("Z", Z), ("K", K)]:
        print(f"{name}={val.hex()}")


if __name__ == "__main__":
    main()
