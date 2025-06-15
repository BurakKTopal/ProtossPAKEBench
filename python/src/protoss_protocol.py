import sodium_bindings as sodium
import hashlib
import os
from dataclasses import dataclass
from typing import List, Tuple

# Constants for the protocol
SCALAR_LEN = sodium.CRYPTO_CORE_RISTRETTO255_SCALARBYTES
POINT_LEN = sodium.CRYPTO_CORE_RISTRETTO255_BYTES
INPUT_LEN_HASH_TO_POINT = 64  # Input size for hash-to-point
SESSION_KEY_LEN = 32  # Output size for session key

@dataclass
class ProtossState:
    """Protoss state structure for maintaining protocol state"""
    x: bytes  # Private key (scalar)
    I: bytes  # Combined point
    P_i: bytes  # Identity of party i
    P_j: bytes  # Identity of party j
    V: bytes  # Hash of password point


class ReturnTypeInit:
    """Return type for Init function"""
    def __init__(self, I: bytes, protoss_state: ProtossState):
        self.I = I
        self.protoss_state = protoss_state


class ReturnTypeRspDer:
    """Return type for RspDer function"""
    def __init__(self, R: bytes, K: bytes):
        self.R = R
        self._K = K

    def get_session_key(self):
        return self._K


def hash_to_point(password: str) -> bytes:
    """Hash password -> 64-byte hash -> map to Ristretto point"""
    # Hash the password to get 64 bytes
    hash_output = hashlib.sha512(password.encode('utf-8')).digest()
    
    # Map the hash to a Ristretto point
    point = sodium.crypto_core_ristretto255_from_hash(hash_output)
    
    return point


def concatenate_bytes(inputs: List[bytes]) -> bytes:
    """Concatenate multiple byte arrays"""
    result = b''
    for data in inputs:
        result += data
    return result


def Init(password: str, P_i: bytes, P_j: bytes) -> ReturnTypeInit:
    """Initialize protocol state (Step 1)"""
    # Choose random x in Z_p
    x = sodium.crypto_core_ristretto255_scalar_random()
    
    # Calculate X = g^x
    X = sodium.crypto_scalarmult_ristretto255_base(x)
    
    # Calculate V = Hash(pwd)
    V = hash_to_point(password)
    
    # Calculate I = X*V ~> X + V in elliptic curves
    I = sodium.crypto_core_ristretto255_add(X, V)
    
    state = ProtossState(x, I, P_i, P_j, V)
    return ReturnTypeInit(I, state)


def RspDer(password: str, P_i: bytes, P_j: bytes, I: bytes) -> ReturnTypeRspDer:
    """Response and key derivation (Step 2)"""
    # Choose random y in Z_p
    y = sodium.crypto_core_ristretto255_scalar_random()
    
    # Calculate Y = g^y
    Y = sodium.crypto_scalarmult_ristretto255_base(y)
    
    # Calculate V = Hash(pwd)
    V = hash_to_point(password)
    
    # Calculate R = Y*V ~> Y + V on the elliptic curve
    R = sodium.crypto_core_ristretto255_add(Y, V)
    
    # Calculates X' = I/V ~> I - V, because I and V are elliptic curve points
    X_prime = sodium.crypto_core_ristretto255_sub(I, V)
    
    # Calculates Z = (X')^y ~> y*X' in elliptic curve calculations
    Z = sodium.crypto_scalarmult_ristretto255(y, X_prime)
    
    # Calculates K = H'(Z, I, R, P_i, P_j, V)
    concat = concatenate_bytes([Z, I, R, P_i, P_j, V])
    K = sodium.crypto_generichash(concat, digest_size=SESSION_KEY_LEN)
    
    return ReturnTypeRspDer(R, K)


def Der(password: str, protoss_state: ProtossState, R: bytes) -> bytes:
    """Key derivation (Step 3)"""
    # Gets state vars
    x, I, P_i, P_j, V = protoss_state.x, protoss_state.I, protoss_state.P_i, protoss_state.P_j, protoss_state.V
    
    # Calculate Y' = R/V ~> R - V because R and V are elliptic curve points
    Y_prime = sodium.crypto_core_ristretto255_sub(R, V)
    
    # Calculates Z = (Y')^x ~> x*Y' in elliptic curve calculations
    Z = sodium.crypto_scalarmult_ristretto255(x, Y_prime)
    
    # Calculates K = H'(Z, I, R, P_i, P_j, V)
    concat = concatenate_bytes([Z, I, R, P_i, P_j, V])
    K = sodium.crypto_generichash(concat, digest_size=SESSION_KEY_LEN)
    
    return K

