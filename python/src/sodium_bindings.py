import ctypes
import os
import sys
from typing import Optional

# Try to load the libsodium library
def _load_libsodium():
    # Look for the library in various locations
    search_paths = [
        # Current directory
        os.path.dirname(os.path.abspath(__file__)),
        # Parent directory
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        # lib directory
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "lib"),
        # parent lib directory
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "lib"),
    ]
    
    lib_names = ["libsodium.dll", "libsodium", "sodium", "libsodium-23.dll"]
    
    for path in search_paths:
        for name in lib_names:
            try:
                full_path = os.path.join(path, name)
                if os.path.exists(full_path):
                    return ctypes.cdll.LoadLibrary(full_path)
            except (OSError, FileNotFoundError):
                pass
    
    # Try system paths
    for name in lib_names:
        try:
            return ctypes.cdll.LoadLibrary(name)
        except (OSError, FileNotFoundError):
            pass
    
    raise RuntimeError("Could not load libsodium library")

# Load the library
_lib = _load_libsodium()

# Define constants
CRYPTO_CORE_RISTRETTO255_BYTES = 32
CRYPTO_CORE_RISTRETTO255_SCALARBYTES = 32
CRYPTO_GENERICHASH_BLAKE2B_BYTES = 32
CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX = 64

# Initialize libsodium
def sodium_init():
    """Initialize libsodium."""
    return _lib.sodium_init()

# Define function signatures and return types
_lib.crypto_core_ristretto255_scalar_random.argtypes = [ctypes.c_void_p]
_lib.crypto_core_ristretto255_scalar_random.restype = ctypes.c_int

_lib.crypto_scalarmult_ristretto255_base.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_lib.crypto_scalarmult_ristretto255_base.restype = ctypes.c_int

_lib.crypto_core_ristretto255_from_hash.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_lib.crypto_core_ristretto255_from_hash.restype = ctypes.c_int

_lib.crypto_core_ristretto255_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_lib.crypto_core_ristretto255_add.restype = ctypes.c_int

_lib.crypto_core_ristretto255_sub.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_lib.crypto_core_ristretto255_sub.restype = ctypes.c_int

_lib.crypto_scalarmult_ristretto255.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_lib.crypto_scalarmult_ristretto255.restype = ctypes.c_int

_lib.crypto_generichash.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_uint64,
    ctypes.c_void_p, ctypes.c_size_t
]
_lib.crypto_generichash.restype = ctypes.c_int

# Wrappers for the libsodium functions

def crypto_core_ristretto255_scalar_random():
    """Generate a random scalar."""
    buf = ctypes.create_string_buffer(CRYPTO_CORE_RISTRETTO255_SCALARBYTES)
    _lib.crypto_core_ristretto255_scalar_random(buf)
    return bytes(buf)

def crypto_scalarmult_ristretto255_base(scalar):
    """Compute the scalar product of a point and the base point."""
    if len(scalar) != CRYPTO_CORE_RISTRETTO255_SCALARBYTES:
        raise ValueError("Invalid scalar length")
    
    point = ctypes.create_string_buffer(CRYPTO_CORE_RISTRETTO255_BYTES)
    scalar_buf = ctypes.create_string_buffer(scalar, CRYPTO_CORE_RISTRETTO255_SCALARBYTES)
    
    if _lib.crypto_scalarmult_ristretto255_base(point, scalar_buf) != 0:
        raise RuntimeError("crypto_scalarmult_ristretto255_base failed")
    
    return bytes(point)

def crypto_core_ristretto255_from_hash(hash_bytes):
    """Map a 64-byte hash to a Ristretto point."""
    if len(hash_bytes) != 64:
        raise ValueError("Invalid hash length")
    
    point = ctypes.create_string_buffer(CRYPTO_CORE_RISTRETTO255_BYTES)
    hash_buf = ctypes.create_string_buffer(hash_bytes, 64)
    
    if _lib.crypto_core_ristretto255_from_hash(point, hash_buf) != 0:
        raise RuntimeError("crypto_core_ristretto255_from_hash failed")
    
    return bytes(point)

def crypto_core_ristretto255_add(point1, point2):
    """Add two Ristretto points."""
    if len(point1) != CRYPTO_CORE_RISTRETTO255_BYTES or len(point2) != CRYPTO_CORE_RISTRETTO255_BYTES:
        raise ValueError("Invalid point length")
    
    result = ctypes.create_string_buffer(CRYPTO_CORE_RISTRETTO255_BYTES)
    p1_buf = ctypes.create_string_buffer(point1, CRYPTO_CORE_RISTRETTO255_BYTES)
    p2_buf = ctypes.create_string_buffer(point2, CRYPTO_CORE_RISTRETTO255_BYTES)
    
    if _lib.crypto_core_ristretto255_add(result, p1_buf, p2_buf) != 0:
        raise RuntimeError("crypto_core_ristretto255_add failed")
    
    return bytes(result)

def crypto_core_ristretto255_sub(point1, point2):
    """Subtract a Ristretto point from another."""
    if len(point1) != CRYPTO_CORE_RISTRETTO255_BYTES or len(point2) != CRYPTO_CORE_RISTRETTO255_BYTES:
        raise ValueError("Invalid point length")
    
    result = ctypes.create_string_buffer(CRYPTO_CORE_RISTRETTO255_BYTES)
    p1_buf = ctypes.create_string_buffer(point1, CRYPTO_CORE_RISTRETTO255_BYTES)
    p2_buf = ctypes.create_string_buffer(point2, CRYPTO_CORE_RISTRETTO255_BYTES)
    
    if _lib.crypto_core_ristretto255_sub(result, p1_buf, p2_buf) != 0:
        raise RuntimeError("crypto_core_ristretto255_sub failed")
    
    return bytes(result)

def crypto_scalarmult_ristretto255(scalar, point):
    """Multiply a Ristretto point by a scalar."""
    if len(scalar) != CRYPTO_CORE_RISTRETTO255_SCALARBYTES or len(point) != CRYPTO_CORE_RISTRETTO255_BYTES:
        raise ValueError("Invalid input length")
    
    result = ctypes.create_string_buffer(CRYPTO_CORE_RISTRETTO255_BYTES)
    scalar_buf = ctypes.create_string_buffer(scalar, CRYPTO_CORE_RISTRETTO255_SCALARBYTES)
    point_buf = ctypes.create_string_buffer(point, CRYPTO_CORE_RISTRETTO255_BYTES)
    
    if _lib.crypto_scalarmult_ristretto255(result, scalar_buf, point_buf) != 0:
        raise RuntimeError("crypto_scalarmult_ristretto255 failed")
    
    return bytes(result)

def crypto_generichash(message, key=None, digest_size=CRYPTO_GENERICHASH_BLAKE2B_BYTES):
    """Compute a BLAKE2b hash."""
    if digest_size > CRYPTO_GENERICHASH_BLAKE2B_BYTES_MAX:
        raise ValueError("Invalid digest size")
    
    buf = ctypes.create_string_buffer(digest_size)
    msg_len = len(message)
    msg_buf = ctypes.create_string_buffer(message, msg_len)
    
    key_buf = None
    key_len = 0
    if key is not None:
        key_len = len(key)
        key_buf = ctypes.create_string_buffer(key, key_len)
    
    if _lib.crypto_generichash(buf, digest_size, msg_buf, msg_len, key_buf, key_len) != 0:
        raise RuntimeError("crypto_generichash failed")
    
    return bytes(buf) 