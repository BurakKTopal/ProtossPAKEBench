import hashlib

import sodium_bindings as sodium
from protoss_protocol import (
    ProtossState, ReturnTypeRspDer,
    hash_to_point, concatenate_bytes,
    SESSION_KEY_LEN,
)


def validated_RspDer(password: str, P_i: bytes, P_j: bytes, I: bytes) -> ReturnTypeRspDer:
    """Response and key derivation (Step 2): validates received point I"""
    if not sodium.crypto_core_ristretto255_is_valid_point(I):
        raise ValueError("invalid Ristretto point I")

    y = sodium.crypto_core_ristretto255_scalar_random()
    Y = sodium.crypto_scalarmult_ristretto255_base(y)
    V = hash_to_point(password)
    R = sodium.crypto_core_ristretto255_add(Y, V)
    X_prime = sodium.crypto_core_ristretto255_sub(I, V)
    Z = sodium.crypto_scalarmult_ristretto255(y, X_prime)

    concat = concatenate_bytes([Z, I, R, P_i, P_j, V])
    K = hashlib.sha512(concat).digest()[:SESSION_KEY_LEN]

    return ReturnTypeRspDer(R, K)


def validated_Der(protoss_state: ProtossState, R: bytes) -> bytes:
    """Key derivation (Step 3): validates received point R"""
    if not sodium.crypto_core_ristretto255_is_valid_point(R):
        raise ValueError("invalid Ristretto point R")

    x, I, P_i, P_j, V = protoss_state.x, protoss_state.I, protoss_state.P_i, protoss_state.P_j, protoss_state.V

    Y_prime = sodium.crypto_core_ristretto255_sub(R, V)
    Z = sodium.crypto_scalarmult_ristretto255(x, Y_prime)

    concat = concatenate_bytes([Z, I, R, P_i, P_j, V])
    K = hashlib.sha512(concat).digest()[:SESSION_KEY_LEN]

    return K
