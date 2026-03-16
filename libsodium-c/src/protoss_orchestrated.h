#ifndef PROTOSS_ORCHESTRATED_H
#define PROTOSS_ORCHESTRATED_H

#include "protoss_common.h"

// State structure for orchestrated variant
typedef struct
{
    unsigned char x[PROTOSS_SCALAR_LEN];
    unsigned char I[PROTOSS_POINT_LEN];
    unsigned char P_i[PROTOSS_MAX_ID_LEN];
    unsigned char P_j[PROTOSS_MAX_ID_LEN];
    unsigned char V[PROTOSS_POINT_LEN];
    size_t P_i_len;
    size_t P_j_len;
} ProtossOrchestratedState;

// Orchestrator: create a zeroed state with party identifiers
int protoss_orchestrated_state_create(ProtossOrchestratedState *state,
                                      const unsigned char *P_i, size_t P_i_len,
                                      const unsigned char *P_j, size_t P_j_len);

// Cleanup: securely wipe sensitive data from state
void protoss_orchestrated_state_destroy(ProtossOrchestratedState *state);

// Initialize protocol (Step 1) - fills state directly by reference
int orchestrated_Init(unsigned char I_out[PROTOSS_POINT_LEN],
                      ProtossOrchestratedState *state,
                      const char *password, size_t password_len);

// Response and key derivation (Step 2) - fills state directly by reference
int orchestrated_RspDer(unsigned char R_out[PROTOSS_POINT_LEN],
                        unsigned char K[PROTOSS_SESSION_KEY_LEN],
                        ProtossOrchestratedState *state,
                        const char *password, size_t password_len,
                        const unsigned char I[PROTOSS_POINT_LEN]);

// Key derivation (Step 3)
int orchestrated_Der(unsigned char K[PROTOSS_SESSION_KEY_LEN],
                     const ProtossOrchestratedState *state,
                     const unsigned char R[PROTOSS_POINT_LEN]);

#endif // PROTOSS_ORCHESTRATED_H
