import hashlib
from dataclasses import dataclass

import sodium_bindings as sodium
from protoss_protocol import (
    ReturnTypeRspDer, hash_to_point, concatenate_bytes,
    POINT_LEN, SCALAR_LEN, SESSION_KEY_LEN,
)


@dataclass
class ProtossOrchestratedState:
    secret_scalar: bytes
    I: bytes
    P_i: bytes
    P_j: bytes
    V: bytes


def orchestrated_state_create(P_i: bytes, P_j: bytes) -> ProtossOrchestratedState:
    """Create a state with party identifiers"""
    return ProtossOrchestratedState(
        secret_scalar=bytes(SCALAR_LEN),
        I=bytes(POINT_LEN),
        P_i=P_i,
        P_j=P_j,
        V=bytes(POINT_LEN),
    )


def orchestrated_state_destroy(state: ProtossOrchestratedState) -> None:
    """Overwrite the secret scalar"""
    state.secret_scalar = bytes(SCALAR_LEN)
    state.V = bytes(POINT_LEN)


def orchestrated_Init(state: ProtossOrchestratedState, password: str) -> bytes:
    """Initialize protocol (Step 1): fills state, returns I"""
    state.secret_scalar = sodium.crypto_core_ristretto255_scalar_random()
    X = sodium.crypto_scalarmult_ristretto255_base(state.secret_scalar)
    state.V = hash_to_point(password)
    state.I = sodium.crypto_core_ristretto255_add(X, state.V)
    return state.I


def orchestrated_RspDer(state: ProtossOrchestratedState, password: str, I: bytes) -> ReturnTypeRspDer:
    """Response and key derivation (Step 2): fills state, returns R and K"""
    state.secret_scalar = sodium.crypto_core_ristretto255_scalar_random()
    Y = sodium.crypto_scalarmult_ristretto255_base(state.secret_scalar)
    state.V = hash_to_point(password)
    R = sodium.crypto_core_ristretto255_add(Y, state.V)
    X_prime = sodium.crypto_core_ristretto255_sub(I, state.V)
    Z = sodium.crypto_scalarmult_ristretto255(state.secret_scalar, X_prime)

    concat = concatenate_bytes([Z, I, R, state.P_i, state.P_j, state.V])
    K = hashlib.sha512(concat).digest()[:SESSION_KEY_LEN]

    return ReturnTypeRspDer(R, K)


def orchestrated_Der(state: ProtossOrchestratedState, R: bytes) -> bytes:
    """Key derivation (Step 3)"""
    Y_prime = sodium.crypto_core_ristretto255_sub(R, state.V)
    Z = sodium.crypto_scalarmult_ristretto255(state.secret_scalar, Y_prime)

    concat = concatenate_bytes([Z, state.I, R, state.P_i, state.P_j, state.V])
    K = hashlib.sha512(concat).digest()[:SESSION_KEY_LEN]

    return K
