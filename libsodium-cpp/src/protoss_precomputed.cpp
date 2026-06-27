#include "protoss_precomputed.hpp"
#include <sodium.h>
#include <stdexcept>

ProtossPrecomputedState precomputed_state_create(const std::vector<unsigned char> &P_i, const std::vector<unsigned char> &P_j)
{
    ProtossPrecomputedState state;
    state.secret_scalar.assign(SCALAR_LEN, 0);
    state.public_point.assign(POINT_LEN, 0);
    state.I.assign(POINT_LEN, 0);
    state.V.assign(POINT_LEN, 0);
    state.P_i = P_i;
    state.P_j = P_j;

    // choose random scalar in Z_p and compute g^scalar
    crypto_core_ristretto255_scalar_random(state.secret_scalar.data());
    if (crypto_scalarmult_ristretto255_base(state.public_point.data(), state.secret_scalar.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255_base failed");

    return state;
}

void precomputed_state_destroy(ProtossPrecomputedState &state)
{
    sodium_memzero(state.secret_scalar.data(), state.secret_scalar.size());
    sodium_memzero(state.V.data(), state.V.size());
}

std::vector<unsigned char> precomputed_Init(ProtossPrecomputedState &state, const std::string &password)
{
    // Calculate V = Hash(pwd)
    state.V = hash_to_point(password);

    // Calculate I = X*V ~> X + V in elliptic curves (X = public_point is precomputed)
    if (crypto_core_ristretto255_add(state.I.data(), state.public_point.data(), state.V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_add failed");

    return state.I;
}

ReturnTypeRspDer precomputed_RspDer(ProtossPrecomputedState &state, const std::string &password, std::vector<unsigned char> I)
{
    // Calculate V = Hash(pwd)
    state.V = hash_to_point(password);

    // Calculate R = Y*V  ~> Y + V on the elliptic curve (Y = public_point is precomputed)
    std::vector<unsigned char> R(POINT_LEN);
    if (crypto_core_ristretto255_add(R.data(), state.public_point.data(), state.V.data()) != 0)
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

std::vector<unsigned char> precomputed_Der(const ProtossPrecomputedState &state, std::vector<unsigned char> R)
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
