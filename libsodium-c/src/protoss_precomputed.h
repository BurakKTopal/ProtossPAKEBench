#ifndef PROTOSS_PRECOMPUTED_H
#define PROTOSS_PRECOMPUTED_H

#include "protoss_common.h"

// Extended state structure with precomputed public point
typedef struct
{
    unsigned char scalar[PROTOSS_SCALAR_LEN];       // x or y (private scalar)
    unsigned char public_point[PROTOSS_POINT_LEN];  // g^x or g^y (precomputed)
    unsigned char I[PROTOSS_POINT_LEN];
    unsigned char P_i[PROTOSS_MAX_ID_LEN];
    unsigned char P_j[PROTOSS_MAX_ID_LEN];
    unsigned char V[PROTOSS_POINT_LEN];
    size_t P_i_len;
    size_t P_j_len;
} ProtossPrecomputedState;

// Orchestrator: create state with precomputed scalar and g^scalar
int protoss_precomputed_state_create(ProtossPrecomputedState *state,
                                     const unsigned char *P_i, size_t P_i_len,
                                     const unsigned char *P_j, size_t P_j_len);

// Cleanup: securely wipe sensitive data from state
void protoss_precomputed_state_destroy(ProtossPrecomputedState *state);

// Initialize protocol (Step 1) - uses precomputed scalar and public_point
int precomputed_Init(unsigned char I_out[PROTOSS_POINT_LEN],
                     ProtossPrecomputedState *state,
                     const char *password, size_t password_len);

// Response and key derivation (Step 2) - uses precomputed scalar and public_point
int precomputed_RspDer(unsigned char R_out[PROTOSS_POINT_LEN],
                       unsigned char K[PROTOSS_SESSION_KEY_LEN],
                       ProtossPrecomputedState *state,
                       const char *password, size_t password_len,
                       const unsigned char I[PROTOSS_POINT_LEN]);

// Key derivation (Step 3)
int precomputed_Der(unsigned char K[PROTOSS_SESSION_KEY_LEN],
                    const ProtossPrecomputedState *state,
                    const unsigned char R[PROTOSS_POINT_LEN]);

#endif // PROTOSS_PRECOMPUTED_H
