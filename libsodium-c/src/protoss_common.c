#include "protoss_common.h"
#include <string.h>

// Hash password -> 64-byte hash -> map to Ristretto point
int protoss_hash_to_point(unsigned char out[PROTOSS_POINT_LEN],
                          const char *password, size_t password_len)
{
    unsigned char hash[PROTOSS_HASH_INPUT_LEN];
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, (const unsigned char *)password, password_len);
    crypto_hash_sha512_final(&st, hash);

    if (crypto_core_ristretto255_from_hash(out, hash) != 0)
        return -1;

    return 0;
}

// Derive session key K = H'(Z, I, R, P_i, P_j, V) using streaming SHA-512
int protoss_derive_session_key(unsigned char K[PROTOSS_SESSION_KEY_LEN],
                               const unsigned char Z[PROTOSS_POINT_LEN],
                               const unsigned char I[PROTOSS_POINT_LEN],
                               const unsigned char R[PROTOSS_POINT_LEN],
                               const unsigned char *P_i, size_t P_i_len,
                               const unsigned char *P_j, size_t P_j_len,
                               const unsigned char V[PROTOSS_POINT_LEN])
{
    crypto_hash_sha512_state st;
    unsigned char h[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, Z, PROTOSS_POINT_LEN);
    crypto_hash_sha512_update(&st, I, PROTOSS_POINT_LEN);
    crypto_hash_sha512_update(&st, R, PROTOSS_POINT_LEN);
    crypto_hash_sha512_update(&st, P_i, P_i_len);
    crypto_hash_sha512_update(&st, P_j, P_j_len);
    crypto_hash_sha512_update(&st, V, PROTOSS_POINT_LEN);
    crypto_hash_sha512_final(&st, h);
    memcpy(K, h, PROTOSS_SESSION_KEY_LEN);
    return 0;
}
