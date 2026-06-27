#include "protoss_orchestrated.hpp"
#include <sodium.h>
#include <stdexcept>

ProtossOrchestratedState orchestrated_state_create(const std::vector<unsigned char> &P_i, const std::vector<unsigned char> &P_j)
{
    ProtossOrchestratedState state;
    state.secret_scalar.assign(SCALAR_LEN, 0);
    state.I.assign(POINT_LEN, 0);
    state.V.assign(POINT_LEN, 0);
    state.P_i = P_i;
    state.P_j = P_j;
    return state;
}

void orchestrated_state_destroy(ProtossOrchestratedState &state)
{
    sodium_memzero(state.secret_scalar.data(), state.secret_scalar.size());
    sodium_memzero(state.V.data(), state.V.size());
}

std::vector<unsigned char> orchestrated_Init(ProtossOrchestratedState &state, const std::string &password)
{
    // choose random x in Z_p
    crypto_core_ristretto255_scalar_random(state.secret_scalar.data());

    // calculate X = g^x
    std::vector<unsigned char> X(POINT_LEN);
    if (crypto_scalarmult_ristretto255_base(X.data(), state.secret_scalar.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255_base failed");

    // Calculate V = Hash(pwd)
    state.V = hash_to_point(password);

    // Calculate I = X*V ~> X + V in elliptic curves
    if (crypto_core_ristretto255_add(state.I.data(), X.data(), state.V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_add failed");

    return state.I;
}

ReturnTypeRspDer orchestrated_RspDer(ProtossOrchestratedState &state, const std::string &password, std::vector<unsigned char> I)
{
    // Choose random y in Z_p
    crypto_core_ristretto255_scalar_random(state.secret_scalar.data());

    // Calculate Y = g^y
    std::vector<unsigned char> Y(POINT_LEN);
    if (crypto_scalarmult_ristretto255_base(Y.data(), state.secret_scalar.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255_base failed");

    // Calculate V = Hash(pwd)
    state.V = hash_to_point(password);

    // Calculate R = Y*V  ~> Y + V on the elliptic curve
    std::vector<unsigned char> R(POINT_LEN);
    if (crypto_core_ristretto255_add(R.data(), Y.data(), state.V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_add failed");

    // Calculates X' = I/V ~> I - V, because I and V are elliptic curve points
    std::vector<unsigned char> X_prime(POINT_LEN);
    if (crypto_core_ristretto255_sub(X_prime.data(), I.data(), state.V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_sub failed");

    // Calculates Z = (X')^y ~> y*X' in elliptic curve calculations
    std::vector<unsigned char> Z(POINT_LEN);
    if (crypto_scalarmult_ristretto255(Z.data(), state.secret_scalar.data(), X_prime.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255 failed");

    // Calculates K = H'(Z, I, R, P_i, P_j, V)
    auto concat = concatenate_vectors({Z, I, R, state.P_i, state.P_j, state.V});
    std::vector<unsigned char> full_hash(crypto_hash_sha512_BYTES);
    if (crypto_hash_sha512(full_hash.data(), concat.data(), concat.size()) != 0)
        throw std::runtime_error("crypto_hash_sha512 failed");
    std::vector<unsigned char> K(full_hash.begin(), full_hash.begin() + SESSION_KEY_LEN);

    return ReturnTypeRspDer(R, K);
}

std::vector<unsigned char> orchestrated_Der(const ProtossOrchestratedState &state, std::vector<unsigned char> R)
{
    // Calculate Y' = R/V ~> R - V because R and V are elliptic curve points
    std::vector<unsigned char> Y_prime(POINT_LEN);
    if (crypto_core_ristretto255_sub(Y_prime.data(), R.data(), state.V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_sub failed");

    // Calculates Z = (Y')^x ~> x*Y' in elliptic curve calculations
    std::vector<unsigned char> Z(POINT_LEN);
    if (crypto_scalarmult_ristretto255(Z.data(), state.secret_scalar.data(), Y_prime.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255 failed");

    // Calculates K = H'(Z, I, R, P_i, P_j, V)
    auto concat = concatenate_vectors({Z, state.I, R, state.P_i, state.P_j, state.V});
    std::vector<unsigned char> full_hash(crypto_hash_sha512_BYTES);
    if (crypto_hash_sha512(full_hash.data(), concat.data(), concat.size()) != 0)
        throw std::runtime_error("crypto_hash_sha512 failed");
    std::vector<unsigned char> K(full_hash.begin(), full_hash.begin() + SESSION_KEY_LEN);

    return K;
}
