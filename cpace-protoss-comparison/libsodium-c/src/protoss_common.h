#ifndef PROTOSS_COMMON_H
#define PROTOSS_COMMON_H

#include <sodium.h>
#include <stddef.h>

// Constants for the protocol
#define PROTOSS_SCALAR_LEN crypto_core_ristretto255_SCALARBYTES
#define PROTOSS_POINT_LEN crypto_core_ristretto255_BYTES
#define PROTOSS_HASH_INPUT_LEN 64 // Input size for crypto_core_ristretto255_from_hash
#define PROTOSS_SESSION_KEY_LEN 32 // Output size for session key
#define PROTOSS_MAX_ID_LEN 32      // Maximum length for party identifiers

// Hash password to point
int protoss_hash_to_point(unsigned char out[PROTOSS_POINT_LEN],
                          const char *password, size_t password_len);

// Derive session key K = H'(Z, I, R, P_i, P_j, V)
int protoss_derive_session_key(unsigned char K[PROTOSS_SESSION_KEY_LEN],
                               const unsigned char Z[PROTOSS_POINT_LEN],
                               const unsigned char I[PROTOSS_POINT_LEN],
                               const unsigned char R[PROTOSS_POINT_LEN],
                               const unsigned char *P_i, size_t P_i_len,
                               const unsigned char *P_j, size_t P_j_len,
                               const unsigned char V[PROTOSS_POINT_LEN]);

#endif // PROTOSS_COMMON_H
