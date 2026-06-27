#![forbid(unsafe_code)]

use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use getrandom::getrandom;
use sha2::{Digest, Sha512};

use crate::ec_operations::{hash_to_point, concatenate_vectors, SCALAR_LEN};
use crate::protoss_protocol::{
    Error, ProtossState, ReturnTypeRspDer, SESSION_ID_BYTES, SESSION_KEY_BYTES,
};

// Response and key derivation (Step 2): validates the received point I
pub fn validated_rsp_der(
    password: &str,
    p_i: &[u8; SESSION_ID_BYTES],
    p_j: &mut [u8; SESSION_ID_BYTES],
    i_bytes: &CompressedRistretto,
) -> Result<ReturnTypeRspDer, Error> {
    // Validate received point I by decompressing it
    let i = i_bytes.decompress().ok_or(Error::InvalidPoint)?;

    let mut y_bytes = [0u8; SCALAR_LEN];
    getrandom(&mut y_bytes)?;
    let y = Scalar::from_bytes_mod_order(y_bytes);

    let y_point = RistrettoPoint::mul_base(&y);
    let v = hash_to_point(password);
    let r = y_point + v;
    let x_prime = i - v;
    let z = y * x_prime;

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

// Key derivation (Step 3): validates the received point R
pub fn validated_der(
    protoss_state: ProtossState,
    r_bytes: &CompressedRistretto,
) -> Result<[u8; SESSION_KEY_BYTES], Error> {
    // Validate received point R by decompressing it
    let r = r_bytes.decompress().ok_or(Error::InvalidPoint)?;

    let ProtossState { x, i, p_i, p_j, v } = protoss_state;

    let y_prime = r - v;
    let z = x * y_prime;

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
