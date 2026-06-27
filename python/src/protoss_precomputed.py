import hashlib
from dataclasses import dataclass

import sodium_bindings as sodium
from protoss_protocol import (
    ReturnTypeRspDer, hash_to_point, concatenate_bytes,
    POINT_LEN, SCALAR_LEN, SESSION_KEY_LEN,
)


@dataclass
class ProtossPrecomputedState:
    secret_scalar: bytes
    public_point: bytes
    I: bytes
    P_i: bytes
    P_j: bytes
    V: bytes


def precomputed_state_create(P_i: bytes, P_j: bytes) -> ProtossPrecomputedState:
    """Create a state with party identifiers and precompute scalar and g^scalar"""
    secret_scalar = sodium.crypto_core_ristretto255_scalar_random()
    public_point = sodium.crypto_scalarmult_ristretto255_base(secret_scalar)
    return ProtossPrecomputedState(
        secret_scalar=secret_scalar,
        public_point=public_point,
        I=bytes(POINT_LEN),
        P_i=P_i,
        P_j=P_j,
        V=bytes(POINT_LEN),
    )


def precomputed_state_destroy(state: ProtossPrecomputedState) -> None:
    """Overwrite the secret scalar"""
    state.secret_scalar = bytes(SCALAR_LEN)
    state.V = bytes(POINT_LEN)


def precomputed_Init(state: ProtossPrecomputedState, password: str) -> bytes:
    """Initialize protocol (Step 1): uses precomputed scalar and public_point, returns I"""
    state.V = hash_to_point(password)
    state.I = sodium.crypto_core_ristretto255_add(state.public_point, state.V)
    return state.I


def precomputed_RspDer(state: ProtossPrecomputedState, password: str, I: bytes) -> ReturnTypeRspDer:
    """Response and key derivation (Step 2): uses precomputed scalar and public_point, returns R and K"""
    state.V = hash_to_point(password)
    R = sodium.crypto_core_ristretto255_add(state.public_point, state.V)
    X_prime = sodium.crypto_core_ristretto255_sub(I, state.V)
    Z = sodium.crypto_scalarmult_ristretto255(state.secret_scalar, X_prime)

    concat = concatenate_bytes([Z, I, R, state.P_i, state.P_j, state.V])
    K = hashlib.sha512(concat).digest()[:SESSION_KEY_LEN]

    return ReturnTypeRspDer(R, K)


def precomputed_Der(state: ProtossPrecomputedState, R: bytes) -> bytes:
    """Key derivation (Step 3)"""
    Y_prime = sodium.crypto_core_ristretto255_sub(R, state.V)
    Z = sodium.crypto_scalarmult_ristretto255(state.secret_scalar, Y_prime)

    concat = concatenate_bytes([Z, state.I, R, state.P_i, state.P_j, state.V])
    K = hashlib.sha512(concat).digest()[:SESSION_KEY_LEN]

    return K
