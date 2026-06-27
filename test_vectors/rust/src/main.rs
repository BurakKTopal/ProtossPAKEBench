use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::{Digest, Sha512};

fn print_hex(name: &str, bytes: &[u8]) {
    print!("{}=", name);
    for b in bytes {
        print!("{:02x}", b);
    }
    println!();
}

fn main() {
    let pwd = b"SharedPassword";
    let p_i = [0x01u8; 16];
    let p_j = [0x02u8; 16];

    let x_bytes: [u8; 32] = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
        0x29, 0x30, 0x41, 0x52, 0x63, 0x74, 0x85, 0x96,
        0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71,
        0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0x00, 0x10,
    ];
    let y_bytes: [u8; 32] = [
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0x00, 0x10,
    ];
    let x = Scalar::from_bytes_mod_order(x_bytes);
    let y = Scalar::from_bytes_mod_order(y_bytes);

    let v = RistrettoPoint::hash_from_bytes::<Sha512>(pwd);
    let i = RistrettoPoint::mul_base(&x) + v;
    let r = RistrettoPoint::mul_base(&y) + v;
    let z = y * (i - v);

    let concat = [
        z.compress().as_bytes().as_ref(),
        i.compress().as_bytes().as_ref(),
        r.compress().as_bytes().as_ref(),
        p_i.as_ref(),
        p_j.as_ref(),
        v.compress().as_bytes().as_ref(),
    ]
    .concat();
    let mut hasher = Sha512::new();
    hasher.update(&concat);
    let hash = hasher.finalize();

    print_hex("V", v.compress().as_bytes());
    print_hex("I", i.compress().as_bytes());
    print_hex("R", r.compress().as_bytes());
    print_hex("Z", z.compress().as_bytes());
    print_hex("K", &hash[..32]);
}
