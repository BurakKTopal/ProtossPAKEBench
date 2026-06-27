#ifndef PROTOSS_PRECOMPUTED_HPP
#define PROTOSS_PRECOMPUTED_HPP

#include <vector>
#include <string>
#include "protoss_protocol.hpp"

// State with a precomputed scalar and public point
struct ProtossPrecomputedState
{
    std::vector<unsigned char> secret_scalar;
    std::vector<unsigned char> public_point;
    std::vector<unsigned char> I;
    std::vector<unsigned char> P_i;
    std::vector<unsigned char> P_j;
    std::vector<unsigned char> V;
};

// Orchestrator: create a state with party identifiers and precompute scalar and g^scalar
ProtossPrecomputedState precomputed_state_create(const std::vector<unsigned char> &P_i,
                                                 const std::vector<unsigned char> &P_j);

// Cleanup: securely wipe sensitive data from state
void precomputed_state_destroy(ProtossPrecomputedState &state);

// Initialize protocol (Step 1): uses precomputed scalar and public_point, returns I
std::vector<unsigned char> precomputed_Init(ProtossPrecomputedState &state,
                                            const std::string &password);

// Response and key derivation (Step 2): uses precomputed scalar and public_point, returns R and K
ReturnTypeRspDer precomputed_RspDer(ProtossPrecomputedState &state,
                                    const std::string &password,
                                    std::vector<unsigned char> I);

// Key derivation (Step 3)
std::vector<unsigned char> precomputed_Der(const ProtossPrecomputedState &state,
                                           std::vector<unsigned char> R);

#endif // PROTOSS_PRECOMPUTED_HPP
