#ifndef PROTOSS_VALIDATED_H
#define PROTOSS_VALIDATED_H

#include "protoss_common.h"

// State structure (identical layout to baseline)
typedef struct
{
    unsigned char x[PROTOSS_SCALAR_LEN];
    unsigned char I[PROTOSS_POINT_LEN];
    unsigned char P_i[PROTOSS_MAX_ID_LEN];
    unsigned char P_j[PROTOSS_MAX_ID_LEN];
    unsigned char V[PROTOSS_POINT_LEN];
    size_t P_i_len;
    size_t P_j_len;
} ProtossValidatedState;

// Return type for validated_Init
typedef struct
{
    unsigned char I[PROTOSS_POINT_LEN];
    ProtossValidatedState state;
} ValidatedReturnTypeInit;

// Return type for validated_RspDer
typedef struct
{
    unsigned char R[PROTOSS_POINT_LEN];
    unsigned char K[PROTOSS_SESSION_KEY_LEN];
} ValidatedReturnTypeRspDer;

// Initialize protocol state (Step 1)
int validated_Init(ValidatedReturnTypeInit *result,
                   const char *password, size_t password_len,
                   const unsigned char *P_i, size_t P_i_len,
                   const unsigned char *P_j, size_t P_j_len);

// Response and key derivation (Step 2) - validates received point I
int validated_RspDer(ValidatedReturnTypeRspDer *result,
                     const char *password, size_t password_len,
                     const unsigned char *P_i, size_t P_i_len,
                     const unsigned char *P_j, size_t P_j_len,
                     const unsigned char I[PROTOSS_POINT_LEN]);

// Key derivation (Step 3) - validates received point R
int validated_Der(unsigned char K[PROTOSS_SESSION_KEY_LEN],
                  const ProtossValidatedState *state,
                  const unsigned char R[PROTOSS_POINT_LEN]);

#endif // PROTOSS_VALIDATED_H
