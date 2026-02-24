#ifndef PROTOSS_PROTOCOL_H
#define PROTOSS_PROTOCOL_H

#include <sodium.h>
#include <stddef.h>

// Constants for the protocol
#define PROTOSS_SCALAR_LEN crypto_core_ristretto255_SCALARBYTES
#define PROTOSS_POINT_LEN crypto_core_ristretto255_BYTES
#define PROTOSS_HASH_INPUT_LEN 64 // Input size for crypto_core_ristretto255_from_hash
#define PROTOSS_SESSION_KEY_LEN 32 // Output size for session key
#define PROTOSS_MAX_ID_LEN 32      // Maximum length for party identifiers

// Protoss state structure for maintaining protocol state
typedef struct
{
    unsigned char x[PROTOSS_SCALAR_LEN];
    unsigned char I[PROTOSS_POINT_LEN];
    unsigned char P_i[PROTOSS_MAX_ID_LEN];
    unsigned char P_j[PROTOSS_MAX_ID_LEN];
    unsigned char V[PROTOSS_POINT_LEN];
    size_t P_i_len;
    size_t P_j_len;
} ProtossState;

// Return type for Init function
typedef struct
{
    unsigned char I[PROTOSS_POINT_LEN];
    ProtossState state;
} ReturnTypeInit;

// Return type for RspDer function
typedef struct
{
    unsigned char R[PROTOSS_POINT_LEN];
    unsigned char K[PROTOSS_SESSION_KEY_LEN];
} ReturnTypeRspDer;

// Hash password to point
int hash_to_point(unsigned char out[PROTOSS_POINT_LEN],
                  const char *password, size_t password_len);

// Initialize protocol state (Step 1)
int Init(ReturnTypeInit *result,
         const char *password, size_t password_len,
         const unsigned char *P_i, size_t P_i_len,
         const unsigned char *P_j, size_t P_j_len);

// Response and key derivation (Step 2)
int RspDer(ReturnTypeRspDer *result,
           const char *password, size_t password_len,
           const unsigned char *P_i, size_t P_i_len,
           const unsigned char *P_j, size_t P_j_len,
           const unsigned char I[PROTOSS_POINT_LEN]);

// Key derivation (Step 3)
int Der(unsigned char K[PROTOSS_SESSION_KEY_LEN],
        const ProtossState *state,
        const unsigned char R[PROTOSS_POINT_LEN]);

#endif // PROTOSS_PROTOCOL_H
