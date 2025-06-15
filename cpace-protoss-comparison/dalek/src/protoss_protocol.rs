#![forbid(unsafe_code)]

use std::fmt;
use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use getrandom::getrandom;
use sha2::{Digest, Sha512};

use crate::ec_operations::{
    hash_to_point, concatenate_vectors,
    SCALAR_LEN,
};

pub const SESSION_KEY_BYTES: usize = 32; // Size of session key
pub const SESSION_ID_BYTES: usize = 16;

#[derive(Debug)]
pub enum Error {
    Random(getrandom::Error),
    InvalidPoint,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Random(e) => write!(f, "Random number generation failed: {:?}", e),
            Error::InvalidPoint => write!(f, "Invalid Ristretto point"),
        }
    }
}

impl From<getrandom::Error> for Error {
    fn from(e: getrandom::Error) -> Self {
        Error::Random(e)
    }
}

// Struct to represent ProtossState
#[derive(Clone)]
pub struct ProtossState {
    pub x: Scalar,
    pub i: RistrettoPoint,
    pub p_i: [u8; SESSION_ID_BYTES],
    pub p_j: [u8; SESSION_ID_BYTES],
    pub v: RistrettoPoint,
}

// Structs for return types
#[derive(Clone)]
pub struct ReturnTypeInit {
    pub i: RistrettoPoint,
    pub state: ProtossState,
}

#[derive(Clone)]
pub struct ReturnTypeRspDer {
    pub r: RistrettoPoint,
    pub k: [u8; SESSION_KEY_BYTES],
}

// Initialize protocol
pub fn init(
    password: &str,
    p_i: &[u8; SESSION_ID_BYTES],
    p_j: &mut [u8; SESSION_ID_BYTES],
) -> Result<ReturnTypeInit, Error> {
    // Choose random x on elliptic curve
    let mut x_bytes = [0u8; SCALAR_LEN];
    getrandom(&mut x_bytes)?;
    let x = Scalar::from_bytes_mod_order(x_bytes);

    // Calculate X = g^x
    let _x_point = RistrettoPoint::mul_base(&x);

    // Calculate V = Hash(pwd), where V must be a point on the curve
    let v = hash_to_point(password);

    // Calculate I = X*V ~> X + V in elliptic curve calculations
    let i = _x_point + v;

    // Create state
    let state = ProtossState {
        x,
        i,
        p_i: *p_i,
        p_j: *p_j,
        v,
    };

    Ok(ReturnTypeInit { i, state })
}

// Responder derivation
pub fn rsp_der(
    password: &str,
    p_i: &[u8; SESSION_ID_BYTES],
    p_j: &mut [u8; SESSION_ID_BYTES],
    i: RistrettoPoint,
) -> Result<ReturnTypeRspDer, Error> {
    // Choose random y on elliptic curve
    let mut y_bytes = [0u8; SCALAR_LEN];
    getrandom(&mut y_bytes)?;

    // Maps to random element on Z_p
    let y = Scalar::from_bytes_mod_order(y_bytes);

    // Calculate Y = g^y
    let _y_point = RistrettoPoint::mul_base(&y);

    // Calculate V = Hash(pwd)
    let v = hash_to_point(password);

    // Calculate R = Y*V ~> Y + V in elliptic curve calculations
    let r = _y_point + v;

    // Calculate X' = I/V ~> I - V, because I and V are elliptic curve points
    let x_prime = i - v;

    // Calculate Z = (X')^y ~> y*X' in elliptic curve calculations
    let z = y*x_prime;

    // Calculate K = H'(Z, I, R, P_i, P_j, V)
    let concat = concatenate_vectors(&[
        z.compress().as_bytes(),
        i.compress().as_bytes(),
        r.compress().as_bytes(),
        p_i.as_ref(),
        p_j.as_ref(),
        v.compress().as_bytes(),
    ]);
    let mut hasher = Sha512::new();
    hasher.update(&concat);
    let hash = hasher.finalize();
    let mut k = [0u8; SESSION_KEY_BYTES];
    k.copy_from_slice(&hash[..SESSION_KEY_BYTES]);

    Ok(ReturnTypeRspDer { r, k })
}

// Derivation
pub fn der(
    _password: &str, 
    protoss_state: ProtossState,
    r: RistrettoPoint,
) -> Result<[u8; SESSION_KEY_BYTES], Error> {
    let ProtossState { x, i, p_i, p_j, v } = protoss_state;

    // Calculate Y' = R/V ~> R - V because R and V are elliptic curve points
    let y_prime = r - v;

    // Calculated Z = (Y')^x ~> x*Y' in elliptic curve calcuations
    let z = x*y_prime;

    // Calculate K = H'(Z, I, R, P_i, P_j, V)
    let concat = concatenate_vectors(&[
        z.compress().as_bytes(),
        i.compress().as_bytes(),
        r.compress().as_bytes(),
        p_i.as_ref(),
        p_j.as_ref(),
        v.compress().as_bytes(),
    ]);
    let mut hasher = Sha512::new();
    hasher.update(&concat);
    let hash = hasher.finalize();
    let mut k = [0u8; SESSION_KEY_BYTES];
    k.copy_from_slice(&hash[..SESSION_KEY_BYTES]);

    Ok(k)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::encode;

    #[test]
    fn test_protoss_protocol() {
        // Initialize inputs
        let password = "my_secure_password";
        let p_i = [1u8; SESSION_ID_BYTES];
        let mut p_j = [2u8; SESSION_ID_BYTES];

        // Step 1: Init
        let init_result = init(password, &p_i, &mut p_j).unwrap();
        let i = init_result.i;

        // Step 2: Responder derivation
        let rsp_der_result = rsp_der(password, &p_i, &mut p_j, i).unwrap();
        let r = rsp_der_result.r;
        let k1 = rsp_der_result.k;

        // Step 3: Derivation
        let k2 = der(password, init_result.state, r).unwrap();

        // Verify keys match
        assert_eq!(k1, k2, "Session keys do not match");
        println!("Session key: {}", encode(k1));
    }
} 