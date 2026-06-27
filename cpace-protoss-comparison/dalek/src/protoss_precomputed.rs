#![forbid(unsafe_code)]

use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use getrandom::getrandom;
use sha2::{Digest, Sha512};

use crate::ec_operations::{hash_to_point, concatenate_vectors, SCALAR_LEN};
use crate::protoss_protocol::{
    Error, ReturnTypeRspDer, SESSION_ID_BYTES, SESSION_KEY_BYTES,
};

// State with a precomputed scalar and public point
pub struct ProtossPrecomputedState {
    pub secret_scalar: Scalar,
    pub public_point: RistrettoPoint,
    pub i: RistrettoPoint,
    pub p_i: [u8; SESSION_ID_BYTES],
    pub p_j: [u8; SESSION_ID_BYTES],
    pub v: RistrettoPoint,
}

// Orchestrator: create a state with party identifiers and precompute scalar and g^scalar
pub fn precomputed_state_create(
    p_i: &[u8; SESSION_ID_BYTES],
    p_j: &[u8; SESSION_ID_BYTES],
) -> Result<ProtossPrecomputedState, Error> {
    let mut scalar_bytes = [0u8; SCALAR_LEN];
    getrandom(&mut scalar_bytes)?;
    let secret_scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    let public_point = RistrettoPoint::mul_base(&secret_scalar);

    Ok(ProtossPrecomputedState {
        secret_scalar,
        public_point,
        i: RistrettoPoint::default(),
        p_i: *p_i,
        p_j: *p_j,
        v: RistrettoPoint::default(),
    })
}

// Cleanup: overwrite the secret scalar
pub fn precomputed_state_destroy(state: &mut ProtossPrecomputedState) {
    state.secret_scalar = Scalar::ZERO;
}

// Initialize protocol (Step 1): uses precomputed scalar and public_point, returns I
pub fn precomputed_init(
    state: &mut ProtossPrecomputedState,
    password: &str,
) -> RistrettoPoint {
    state.v = hash_to_point(password);
    state.i = state.public_point + state.v;
    state.i
}
ç
// Response and key derivation (Step 2): uses precomputed scalar and public_point, returns R and K
pub fn precomputed_rsp_der(
    state: &mut ProtossPrecomputedState,
    password: &str,
    i: RistrettoPoint,
) -> Result<ReturnTypeRspDer, Error> {
    state.v = hash_to_point(password);
    let r = state.public_point + state.v;
    let x_prime = i - state.v;
    let z = state.secret_scalar * x_prime;

    let concat = concatenate_vectors(&[
        z.compress().as_bytes(),
        i.compress().as_bytes(),
        r.compress().as_bytes(),
        state.p_i.as_ref(),
        state.p_j.as_ref(),
        state.v.compress().as_bytes(),
    ]);
    let mut hasher = Sha512::new();
    hasher.update(&concat);
    let hash = hasher.finalize();
    let mut k = [0u8; SESSION_KEY_BYTES];
    k.copy_from_slice(&hash[..SESSION_KEY_BYTES]);

    Ok(ReturnTypeRspDer { r, k })
}

// Key derivation (Step 3)
pub fn precomputed_der(
    state: &ProtossPrecomputedState,
    r: RistrettoPoint,
) -> Result<[u8; SESSION_KEY_BYTES], Error> {
    let y_prime = r - state.v;
    let z = state.secret_scalar * y_prime;

    let concat = concatenate_vectors(&[
        z.compress().as_bytes(),
        state.i.compress().as_bytes(),
        r.compress().as_bytes(),
        state.p_i.as_ref(),
        state.p_j.as_ref(),
        state.v.compress().as_bytes(),
    ]);
    let mut hasher = Sha512::new();
    hasher.update(&concat);
    let hash = hasher.finalize();
    let mut k = [0u8; SESSION_KEY_BYTES];
    k.copy_from_slice(&hash[..SESSION_KEY_BYTES]);

    Ok(k)
}
