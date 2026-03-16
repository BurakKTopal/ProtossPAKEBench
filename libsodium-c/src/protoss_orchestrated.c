#include "protoss_orchestrated.h"
#include <string.h>

int protoss_orchestrated_state_create(ProtossOrchestratedState *state,
                                      const unsigned char *P_i, size_t P_i_len,
                                      const unsigned char *P_j, size_t P_j_len)
{
    // Zero the entire state
    memset(state, 0, sizeof(ProtossOrchestratedState));

    // Copy party identifiers
    memcpy(state->P_i, P_i, P_i_len);
    state->P_i_len = P_i_len;
    memcpy(state->P_j, P_j, P_j_len);
    state->P_j_len = P_j_len;

    return 0;
}

void protoss_orchestrated_state_destroy(ProtossOrchestratedState *state)
{
    sodium_memzero(state, sizeof(ProtossOrchestratedState));
}

int orchestrated_Init(unsigned char I_out[PROTOSS_POINT_LEN],
                      ProtossOrchestratedState *state,
                      const char *password, size_t password_len)
{
    unsigned char X[PROTOSS_POINT_LEN];

    // choose random x in Z_p
    crypto_core_ristretto255_scalar_random(state->x);

    // calculate X = g^x
    if (crypto_scalarmult_ristretto255_base(X, state->x) != 0)
        return -1;

    // Calculate V = Hash(pwd)
    if (protoss_hash_to_point(state->V, password, password_len) != 0)
        return -1;

    // Calculate I = X*V ~> X + V in elliptic curves
    if (crypto_core_ristretto255_add(state->I, X, state->V) != 0)
        return -1;

    // Output I for sending to responder
    memcpy(I_out, state->I, PROTOSS_POINT_LEN);

    return 0;
}

int orchestrated_RspDer(unsigned char R_out[PROTOSS_POINT_LEN],
                        unsigned char K[PROTOSS_SESSION_KEY_LEN],
                        ProtossOrchestratedState *state,
                        const char *password, size_t password_len,
                        const unsigned char I[PROTOSS_POINT_LEN])
{
    unsigned char Y[PROTOSS_POINT_LEN];
    unsigned char R[PROTOSS_POINT_LEN];
    unsigned char X_prime[PROTOSS_POINT_LEN];
    unsigned char Z[PROTOSS_POINT_LEN];

    // Choose random y in Z_p
    crypto_core_ristretto255_scalar_random(state->x);

    // Calculate Y = g^y
    if (crypto_scalarmult_ristretto255_base(Y, state->x) != 0)
        return -1;

    // Calculate V = Hash(pwd)
    if (protoss_hash_to_point(state->V, password, password_len) != 0)
        return -1;

    // Calculate R = Y*V  ~> Y + V on the elliptic curve
    if (crypto_core_ristretto255_add(R, Y, state->V) != 0)
        return -1;

    // Calculates X' = I/V ~> I - V, because I and V are elliptic curve points
    if (crypto_core_ristretto255_sub(X_prime, I, state->V) != 0)
        return -1;

    // Calculates Z = (X')^y ~> y*X' in elliptic curve calculations
    if (crypto_scalarmult_ristretto255(Z, state->x, X_prime) != 0)
        return -1;

    // Calculates K = H'(Z, I, R, P_i, P_j, V)
    if (protoss_derive_session_key(K, Z, I, R,
                                   state->P_i, state->P_i_len,
                                   state->P_j, state->P_j_len,
                                   state->V) != 0)
        return -1;

    memcpy(state->I, R, PROTOSS_POINT_LEN);
    memcpy(R_out, R, PROTOSS_POINT_LEN);

    return 0;
}

int orchestrated_Der(unsigned char K[PROTOSS_SESSION_KEY_LEN],
                     const ProtossOrchestratedState *state,
                     const unsigned char R[PROTOSS_POINT_LEN])
{
    unsigned char Y_prime[PROTOSS_POINT_LEN];
    unsigned char Z[PROTOSS_POINT_LEN];

    // Calculate Y' = R/V ~> R - V because R and V are elliptic curve points
    if (crypto_core_ristretto255_sub(Y_prime, R, state->V) != 0)
        return -1;

    // Calculates Z = (Y')^x ~> x*Y' in elliptic curve calculations
    if (crypto_scalarmult_ristretto255(Z, state->x, Y_prime) != 0)
        return -1;

    // Calculates K = H'(Z, I, R, P_i, P_j, V)
    if (protoss_derive_session_key(K, Z, state->I, R,
                                   state->P_i, state->P_i_len,
                                   state->P_j, state->P_j_len,
                                   state->V) != 0)
        return -1;

    return 0;
}
