#include <cstdio>
#include <cstring>
#include <vector>
#include <sodium.h>

static const size_t POINT_LEN = crypto_core_ristretto255_BYTES;
static const size_t SCALAR_LEN = crypto_core_ristretto255_SCALARBYTES;
static const size_t KEY_LEN = 32;

static void print_hex(const char *name, const unsigned char *buf, size_t len)
{
    std::printf("%s=", name);
    for (size_t i = 0; i < len; i++)
        std::printf("%02x", buf[i]);
    std::printf("\n");
}

int main()
{
    if (sodium_init() < 0)
        return 1;

    const char *pwd = "SharedPassword";
    unsigned char P_i[16], P_j[16];
    std::memset(P_i, 0x01, sizeof(P_i));
    std::memset(P_j, 0x02, sizeof(P_j));

    unsigned char x[SCALAR_LEN] = {
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
        0x29, 0x30, 0x41, 0x52, 0x63, 0x74, 0x85, 0x96,
        0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
        0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0x00, 0x10};
    unsigned char y[SCALAR_LEN] = {
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0x00, 0x10};

    unsigned char hash[64], V[POINT_LEN], X[POINT_LEN], Y[POINT_LEN];
    unsigned char I[POINT_LEN], R[POINT_LEN], X_prime[POINT_LEN], Z[POINT_LEN];

    crypto_hash_sha512(hash, reinterpret_cast<const unsigned char *>(pwd), std::strlen(pwd));
    if (crypto_core_ristretto255_from_hash(V, hash) != 0)
        return 1;
    if (crypto_scalarmult_ristretto255_base(X, x) != 0)
        return 1;
    if (crypto_scalarmult_ristretto255_base(Y, y) != 0)
        return 1;
    if (crypto_core_ristretto255_add(I, X, V) != 0)
        return 1;
    if (crypto_core_ristretto255_add(R, Y, V) != 0)
        return 1;
    if (crypto_core_ristretto255_sub(X_prime, I, V) != 0)
        return 1;
    if (crypto_scalarmult_ristretto255(Z, y, X_prime) != 0)
        return 1;

    crypto_hash_sha512_state st;
    unsigned char h[64], K[KEY_LEN];
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, Z, POINT_LEN);
    crypto_hash_sha512_update(&st, I, POINT_LEN);
    crypto_hash_sha512_update(&st, R, POINT_LEN);
    crypto_hash_sha512_update(&st, P_i, sizeof(P_i));
    crypto_hash_sha512_update(&st, P_j, sizeof(P_j));
    crypto_hash_sha512_update(&st, V, POINT_LEN);
    crypto_hash_sha512_final(&st, h);
    std::memcpy(K, h, KEY_LEN);

    print_hex("V", V, POINT_LEN);
    print_hex("I", I, POINT_LEN);
    print_hex("R", R, POINT_LEN);
    print_hex("Z", Z, POINT_LEN);
    print_hex("K", K, KEY_LEN);
    return 0;
}
