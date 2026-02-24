#ifndef PROTOSS_PROTOCOL_HPP
#define PROTOSS_PROTOCOL_HPP

#include <vector>
#include <string>
#include <sodium.h>
#include <stdexcept>

// Constants for the protocol
constexpr size_t SCALAR_LEN = crypto_core_ristretto255_SCALARBYTES;
constexpr size_t POINT_LEN = crypto_core_ristretto255_BYTES;
constexpr size_t INPUT_LEN_RISTRETTO_HASH_TO_POINT = 64; // Input size for crypto_core_ristretto255_from_hash
constexpr size_t SESSION_KEY_LEN = 32;                   // Output size for session key

// Protoss state structure for maintaining protocol state
struct ProtossState
{
    std::vector<unsigned char> x, I, P_i, P_j, V;
    ProtossState(const std::vector<unsigned char> &x,
                 const std::vector<unsigned char> &I,
                 const std::vector<unsigned char> &P_i,
                 const std::vector<unsigned char> &P_j,
                 const std::vector<unsigned char> &V)
        : x(x), I(I), P_i(P_i), P_j(P_j), V(V) {}
};

// Return type for Init function
struct ReturnTypeInit
{
    std::vector<unsigned char> I;
    ProtossState &protoss_state;
    ReturnTypeInit(const std::vector<unsigned char> &I, ProtossState &protoss_state)
        : I(I), protoss_state(protoss_state) {}
};

// Return type for RspDer function
struct ReturnTypeRspDer
{
private:
    std::vector<unsigned char> K;

public:
    std::vector<unsigned char> R;
    std::vector<unsigned char> getSessionKey() { return K; }
    ReturnTypeRspDer(std::vector<unsigned char> R, std::vector<unsigned char> K) : R(R), K(K) {}
};

// Hash password to point
std::vector<unsigned char> hash_to_point(const std::string &password);

// Concatenate multiple byte vectors
std::vector<unsigned char> concatenate_vectors(const std::vector<std::vector<unsigned char>> &inputs);

// Initialize protocol state (Step 1)
ReturnTypeInit Init(const std::string &password,
                    const std::vector<unsigned char> &P_i,
                    std::vector<unsigned char> &P_j);

// Response and key derivation (Step 2)
ReturnTypeRspDer RspDer(const std::string &password,
                        const std::vector<unsigned char> &P_i,
                        std::vector<unsigned char> &P_j,
                        std::vector<unsigned char> I);

// Key derivation (Step 3)
std::vector<unsigned char> Der(const std::string &password,
                               ProtossState protoss_state,
                               std::vector<unsigned char> R);

// Utility to calculate bit length of data
size_t get_bit_length(const std::vector<unsigned char> &data);

#endif // PROTOSS_PROTOCOL_HPP