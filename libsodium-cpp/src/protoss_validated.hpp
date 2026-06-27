#ifndef PROTOSS_VALIDATED_HPP
#define PROTOSS_VALIDATED_HPP

#include <vector>
#include <string>
#include "protoss_protocol.hpp"

// Response and key derivation (Step 2): validates received point I
ReturnTypeRspDer validated_RspDer(const std::string &password,
                                  const std::vector<unsigned char> &P_i,
                                  std::vector<unsigned char> &P_j,
                                  std::vector<unsigned char> I);

// Key derivation (Step 3): validates received point R
std::vector<unsigned char> validated_Der(ProtossState protoss_state,
                                         std::vector<unsigned char> R);

#endif // PROTOSS_VALIDATED_HPP
