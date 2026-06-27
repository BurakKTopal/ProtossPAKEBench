#![forbid(unsafe_code)]

use curve25519_dalek::{
    ristretto::RistrettoPoint,
};
use sha2::Sha512;

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