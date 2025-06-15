
#include "protoss_protocol.hpp"

// Hash password -> 64-byte hash -> map to Ristretto point
std::vector<unsigned char> hash_to_point(const std::string &password)
{
    std::vector<unsigned char> hash(INPUT_LEN_RISTRETTO_HASH_TO_POINT, 0);
    if (crypto_generichash(hash.data(), hash.size(), (const unsigned char *)password.data(), password.size(), nullptr, 0) != 0)
        throw std::runtime_error("crypto_generichash failed");

    std::vector<unsigned char> point(POINT_LEN, 0);
    if (crypto_core_ristretto255_from_hash(point.data(), hash.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_from_hash failed");

    return point;
}

// Concatenate multiple byte vectors
std::vector<unsigned char> concatenate_vectors(const std::vector<std::vector<unsigned char>> &inputs)
{
    std::vector<unsigned char> result;
    for (const auto &vec : inputs)
        result.insert(result.end(), vec.begin(), vec.end());
    return result;
}

ReturnTypeInit Init(const std::string &password, const std::vector<unsigned char> &P_i, std::vector<unsigned char> &P_j)
{

    // choose random x in Z_p
    std::vector<unsigned char> x(SCALAR_LEN);
    crypto_core_ristretto255_scalar_random(x.data());

    // calculate X = g^x
    std::vector<unsigned char> X(POINT_LEN);
    if (crypto_scalarmult_ristretto255_base(X.data(), x.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255_base failed");

    // Calculate V = Hash(pwd)
    std::vector<unsigned char> V = hash_to_point(password);

    // Calculate I = X*V ~> X + V in elliptic curves
    std::vector<unsigned char> I(POINT_LEN);
    if (crypto_core_ristretto255_add(I.data(), X.data(), V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_add failed");

    ProtossState *state = new ProtossState(x, I, P_i, P_j, V);
    return ReturnTypeInit(I, *state);
}

ReturnTypeRspDer RspDer(const std::string &password, const std::vector<unsigned char> &P_i, std::vector<unsigned char> &P_j, std::vector<unsigned char> I)
{

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
    std::vector<unsigned char> K(SESSION_KEY_LEN);
    auto concat = concatenate_vectors({Z, I, R, P_i, P_j, V});
    if (crypto_generichash(K.data(), K.size(), concat.data(), concat.size(), nullptr, 0) != 0)
        throw std::runtime_error("crypto_generichash failed");

    return ReturnTypeRspDer(R, K);
}

std::vector<unsigned char> Der(const std::string &password, ProtossState protoss_state, std::vector<unsigned char> R)
{

    // Gets state vars
    auto &[x, I, P_i, P_j, V] = protoss_state;

    // Calculate Y' = R/V ~> R - V because R and V are elliptic curve points
    std::vector<unsigned char> Y_prime(POINT_LEN);
    if (crypto_core_ristretto255_sub(Y_prime.data(), R.data(), V.data()) != 0)
        throw std::runtime_error("crypto_core_ristretto255_sub failed");

    // Calculates Z = (Y')^x ~> x*Y' in elliptic curve calcuations
    std::vector<unsigned char> Z(POINT_LEN);
    if (crypto_scalarmult_ristretto255(Z.data(), x.data(), Y_prime.data()) != 0)
        throw std::runtime_error("crypto_scalarmult_ristretto255 failed");

    // Calculates K = H'(Z, I, R, P_i, P_j, V)
    std::vector<unsigned char> K(SESSION_KEY_LEN);
    auto concat = concatenate_vectors({Z, I, R, P_i, P_j, V});
    if (crypto_generichash(K.data(), K.size(), concat.data(), concat.size(), nullptr, 0) != 0)
        throw std::runtime_error("crypto_generichash failed");

    return K;
}