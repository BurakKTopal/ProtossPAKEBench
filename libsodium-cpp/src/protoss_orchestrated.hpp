#ifndef PROTOSS_ORCHESTRATED_HPP
#define PROTOSS_ORCHESTRATED_HPP

#include <vector>
#include <string>
#include "protoss_protocol.hpp"

// State managed by the orchestrator and filled by the protocol steps
struct ProtossOrchestratedState
{
    std::vector<unsigned char> secret_scalar;
    std::vector<unsigned char> I;
    std::vector<unsigned char> P_i;
    std::vector<unsigned char> P_j;
    std::vector<unsigned char> V;
};

// Orchestrator: create a state with party identifiers
ProtossOrchestratedState orchestrated_state_create(const std::vector<unsigned char> &P_i,
                                                   const std::vector<unsigned char> &P_j);

// Cleanup: securely wipe sensitive data from state
void orchestrated_state_destroy(ProtossOrchestratedState &state);

// Initialize protocol (Step 1): fills state by reference, returns I
std::vector<unsigned char> orchestrated_Init(ProtossOrchestratedState &state,
                                             const std::string &password);

// Response and key derivation (Step 2): fills state by reference, returns R and K
ReturnTypeRspDer orchestrated_RspDer(ProtossOrchestratedState &state,
                                     const std::string &password,
                                     std::vector<unsigned char> I);

// Key derivation (Step 3)
std::vector<unsigned char> orchestrated_Der(const ProtossOrchestratedState &state,
                                            std::vector<unsigned char> R);

#endif // PROTOSS_ORCHESTRATED_HPP
