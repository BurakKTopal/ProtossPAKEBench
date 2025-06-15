#![forbid(unsafe_code)]

use curve25519_dalek::{
    ristretto::RistrettoPoint,
};
use sha2::{Digest, Sha512};

pub const INPUT_LEN_RISTRETTO_HASH_TO_POINT: usize = 64; // Hash size for ristretto255
pub const POINT_LEN: usize = 32; // Size of a ristretto255 point
pub const SCALAR_LEN: usize = 32; // Size of a ristretto255 scalar

// Hash password to a Ristretto point
pub fn hash_to_point(password: &str) -> RistrettoPoint {
    RistrettoPoint::hash_from_bytes::<Sha512>(password.as_bytes())
}

// Concatenate multiple byte arrays
pub fn concatenate_vectors(inputs: &[&[u8]]) -> Vec<u8> {
    inputs.iter().flat_map(|&vec| vec.iter().copied()).collect()
}

// Get bit length of data
pub fn get_bit_length(data: &[u8]) -> usize {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            let mut leading_zeros = 0;
            let mut test_byte = byte;
            while (test_byte & 0x80) == 0 {
                test_byte <<= 1;
                leading_zeros += 1;
            }
            return (data.len() - i) * 8 - leading_zeros;
        }
    }
    0
} 