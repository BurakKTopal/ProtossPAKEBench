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

// State managed by the orchestrator and filled by the protocol steps
pub struct ProtossOrchestratedState {
    pub secret_scalar: Scalar,
    pub i: RistrettoPoint,
    pub p_i: [u8; SESSION_ID_BYTES],
    pub p_j: [u8; SESSION_ID_BYTES],
    pub v: RistrettoPoint,
}

// Orchestrator: create a state with party identifiers
pub fn orchestrated_state_create(
    p_i: &[u8; SESSION_ID_BYTES],
    p_j: &[u8; SESSION_ID_BYTES],
) -> ProtossOrchestratedState {
    ProtossOrchestratedState {
        secret_scalar: Scalar::ZERO,
        i: RistrettoPoint::default(),
        p_i: *p_i,
        p_j: *p_j,
        v: RistrettoPoint::default(),
    }
}

// Cleanup: overwrite the secret scalar
pub fn orchestrated_state_destroy(state: &mut ProtossOrchestratedState) {
    state.secret_scalar = Scalar::ZERO;
}

// Initialize protocol (Step 1): fills state by reference, returns I
pub fn orchestrated_init(
    state: &mut ProtossOrchestratedState,
    password: &str,
) -> Result<RistrettoPoint, Error> {
    let mut x_bytes = [0u8; SCALAR_LEN];
    getrandom(&mut x_bytes)?;
    state.secret_scalar = Scalar::from_bytes_mod_order(x_bytes);

    let x_point = RistrettoPoint::mul_base(&state.secret_scalar);
    state.v = hash_to_point(password);
    state.i = x_point + state.v;

    Ok(state.i)
}

// Response and key derivation (Step 2): fills state by reference, returns R and K
pub fn orchestrated_rsp_der(
    state: &mut ProtossOrchestratedState,
    password: &str,
    i: RistrettoPoint,
) -> Result<ReturnTypeRspDer, Error> {
    let mut y_bytes = [0u8; SCALAR_LEN];
    getrandom(&mut y_bytes)?;
    state.secret_scalar = Scalar::from_bytes_mod_order(y_bytes);

    let y_point = RistrettoPoint::mul_base(&state.secret_scalar);
    state.v = hash_to_point(password);
    let r = y_point + state.v;
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
pub fn orchestrated_der(
    state: &ProtossOrchestratedState,
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
