#include "protoss_validated.h"
#include <string.h>

int validated_Init(ValidatedReturnTypeInit *result,
                   const char *password, size_t password_len,
                   const unsigned char *P_i, size_t P_i_len,
                   const unsigned char *P_j, size_t P_j_len)
{
    unsigned char x[PROTOSS_SCALAR_LEN];
    unsigned char X[PROTOSS_POINT_LEN];
    unsigned char V[PROTOSS_POINT_LEN];
    unsigned char I[PROTOSS_POINT_LEN];

    // choose random x in Z_p
    crypto_core_ristretto255_scalar_random(x);

    // calculate X = g^x
    if (crypto_scalarmult_ristretto255_base(X, x) != 0)
        return -1;

    // Calculate V = Hash(pwd)
    if (protoss_hash_to_point(V, password, password_len) != 0)
        return -1;

    // Calculate I = X*V ~> X + V in elliptic curves
    if (crypto_core_ristretto255_add(I, X, V) != 0)
        return -1;

    // Populate result
    memcpy(result->I, I, PROTOSS_POINT_LEN);
    memcpy(result->state.x, x, PROTOSS_SCALAR_LEN);
    memcpy(result->state.I, I, PROTOSS_POINT_LEN);
    memcpy(result->state.V, V, PROTOSS_POINT_LEN);
    memset(result->state.P_i, 0, PROTOSS_MAX_ID_LEN);
    memcpy(result->state.P_i, P_i, P_i_len);
    result->state.P_i_len = P_i_len;
    memset(result->state.P_j, 0, PROTOSS_MAX_ID_LEN);
    memcpy(result->state.P_j, P_j, P_j_len);
    result->state.P_j_len = P_j_len;

    return 0;
}

int validated_RspDer(ValidatedReturnTypeRspDer *result,
                     const char *password, size_t password_len,
                     const unsigned char *P_i, size_t P_i_len,
                     const unsigned char *P_j, size_t P_j_len,
                     const unsigned char I[PROTOSS_POINT_LEN])
{
    unsigned char y[PROTOSS_SCALAR_LEN];
    unsigned char Y[PROTOSS_POINT_LEN];
    unsigned char V[PROTOSS_POINT_LEN];
    unsigned char R[PROTOSS_POINT_LEN];
    unsigned char X_prime[PROTOSS_POINT_LEN];
    unsigned char Z[PROTOSS_POINT_LEN];

    // Validate received point I
    if (crypto_core_ristretto255_is_valid_point(I) != 1)
        return -1;

    // Choose random y in Z_p
    crypto_core_ristretto255_scalar_random(y);

    // Calculate Y = g^y
    if (crypto_scalarmult_ristretto255_base(Y, y) != 0)
        return -1;

    // Calculate V = Hash(pwd)
    if (protoss_hash_to_point(V, password, password_len) != 0)
        return -1;

    // Calculate R = Y*V  ~> Y + V on the elliptic curve
    if (crypto_core_ristretto255_add(R, Y, V) != 0)
        return -1;

    // Calculates X' = I/V ~> I - V, because I and V are elliptic curve points
    if (crypto_core_ristretto255_sub(X_prime, I, V) != 0)
        return -1;

    // Calculates Z = (X')^y ~> y*X' in elliptic curve calculations
    if (crypto_scalarmult_ristretto255(Z, y, X_prime) != 0)
        return -1;

    // Calculates K = H'(Z, I, R, P_i, P_j, V)
    if (protoss_derive_session_key(result->K, Z, I, R, P_i, P_i_len, P_j, P_j_len, V) != 0)
        return -1;

    memcpy(result->R, R, PROTOSS_POINT_LEN);
    return 0;
}

int validated_Der(unsigned char K[PROTOSS_SESSION_KEY_LEN],
                  const ProtossValidatedState *state,
                  const unsigned char R[PROTOSS_POINT_LEN])
{
    unsigned char Y_prime[PROTOSS_POINT_LEN];
    unsigned char Z[PROTOSS_POINT_LEN];

    // Validate received point R
    if (crypto_core_ristretto255_is_valid_point(R) != 1)
        return -1;

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
