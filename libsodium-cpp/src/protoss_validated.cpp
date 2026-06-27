#include "protoss_validated.hpp"
#include <sodium.h>
#include <stdexcept>

ReturnTypeRspDer validated_RspDer(const std::string &password, const std::vector<unsigned char> &P_i, std::vector<unsigned char> &P_j, std::vector<unsigned char> I)
{
    // Validate received point I
    if (crypto_core_ristretto255_is_valid_point(I.data()) != 1)
        throw std::runtime_error("invalid Ristretto point I");

    // Choose random y in Z_p
    std::vector<unsigned char> y(SCALAR_LEN);
    crypto_core_ristretto255_scalar_random(y.data());

    // Calculate Y = g^y
    std::vector<unsigned char> Y(POINT_LEN);
    if (crypto_scalarmult_ristretto255_base(Y.data(), y.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255_base failed");

    // Calculate V = Hash(pwd)
    std::vector<unsigned char> V = hash_to_point(password);

    // Calculate R = Y*V  ~> Y + V on the elliptic curve
    std::vector<unsigned char> R(POINT_LEN);
    if (crypto_core_ristretto255_add(R.data(), Y.data(), V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_add failed");

    // Calculates X' = I/V ~> I - V, because I and V are elliptic curve points
    std::vector<unsigned char> X_prime(POINT_LEN);
    if (crypto_core_ristretto255_sub(X_prime.data(), I.data(), V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_sub failed");

    // Calculates Z = (X')^y ~> y*X' in elliptic curve calculations
    std::vector<unsigned char> Z(POINT_LEN);
    if (crypto_scalarmult_ristretto255(Z.data(), y.data(), X_prime.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255 failed");

    // Calculates K = H'(Z, I, R, P_i, P_j, V)
    auto concat = concatenate_vectors({Z, I, R, P_i, P_j, V});
    std::vector<unsigned char> full_hash(crypto_hash_sha512_BYTES);
    if (crypto_hash_sha512(full_hash.data(), concat.data(), concat.size()) != 0)
        throw std::runtime_error("crypto_hash_sha512 failed");
    std::vector<unsigned char> K(full_hash.begin(), full_hash.begin() + SESSION_KEY_LEN);

    return ReturnTypeRspDer(R, K);
}

std::vector<unsigned char> validated_Der(ProtossState protoss_state, std::vector<unsigned char> R)
{
    // Validate received point R
    if (crypto_core_ristretto255_is_valid_point(R.data()) != 1)
        throw std::runtime_error("invalid Ristretto point R");

    auto &[x, I, P_i, P_j, V] = protoss_state;

    // Calculate Y' = R/V ~> R - V because R and V are elliptic curve points
    std::vector<unsigned char> Y_prime(POINT_LEN);
    if (crypto_core_ristretto255_sub(Y_prime.data(), R.data(), V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_sub failed");

    // Calculates Z = (Y')^x ~> x*Y' in elliptic curve calculations
    std::vector<unsigned char> Z(POINT_LEN);
    if (crypto_scalarmult_ristretto255(Z.data(), x.data(), Y_prime.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255 failed");

    // Calculates K = H'(Z, I, R, P_i, P_j, V)
    auto concat = concatenate_vectors({Z, I, R, P_i, P_j, V});
    std::vector<unsigned char> full_hash(crypto_hash_sha512_BYTES);
    if (crypto_hash_sha512(full_hash.data(), concat.data(), concat.size()) != 0)
        throw std::runtime_error("crypto_hash_sha512 failed");
    std::vector<unsigned char> K(full_hash.begin(), full_hash.begin() + SESSION_KEY_LEN);

    return K;
}
