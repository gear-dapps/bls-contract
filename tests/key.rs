use bls::key::{key_gen, PrivateKey, PublicKey};
use bls12_381::Scalar;
use ff::PrimeField;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[test]
fn test_bytes_roundtrip() {
    let rng = &mut ChaCha8Rng::seed_from_u64(12);
    let sk = PrivateKey::generate(rng);
    let sk_bytes = sk.as_bytes();

    assert_eq!(sk_bytes.len(), 32);
    assert_eq!(PrivateKey::from_bytes(&sk_bytes).unwrap(), sk);

    let pk = sk.public_key();
    let pk_bytes = pk.as_bytes();

    assert_eq!(pk_bytes.len(), 48);
    assert_eq!(PublicKey::from_bytes(&pk_bytes).unwrap(), pk);
}

#[test]
fn test_key_gen() {
    let key_material = "hello world (it's a secret!) very secret stuff";
    let fr_val = key_gen(key_material);

    let expect = Scalar::from_raw([
        0xa9f8187b89e6d49a,
        0xf870f34063ce4b16,
        0xc2aa3c1fff1bbaa3,
        0x60417787ee46e23f,
    ]);

    assert_eq!(fr_val, expect);
}

#[test]
fn test_sig() {
    let msg = "this is the message";
    let sk = "this is the key and it is very secret";

    let sk = PrivateKey::new(sk);
    let sig = sk.sign(msg);
    let pk = sk.public_key();

    assert!(pk.verify(sig, msg));
}

#[test]
fn test_from_bytes() {
    // Larger than the modulus
    assert!(PrivateKey::from_bytes(&[255u8; 32]).is_err());

    // Scalar field modulus' bigint (i.e. non-Montgomery form) little-endian bytes.
    let modulus_repr: [u8; 32] = [
        0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd,
        0x53, 0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7,
        0xed, 0x73,
    ];

    // Largest field element.
    let neg1_repr: [u8; 32] = {
        let mut repr = modulus_repr;
        repr[0] -= 1;
        repr
    };
    assert!(PrivateKey::from_bytes(&neg1_repr).is_ok());

    // Smallest integer greater than the modulus.
    let modulus_plus_1_repr = {
        let mut repr = modulus_repr;
        repr[0] += 1;
        repr
    };
    assert!(PrivateKey::from_bytes(&modulus_plus_1_repr).is_err());

    // simple numbers below the modulus
    assert!(PrivateKey::from_bytes(&Scalar::from(1).to_repr()).is_ok());
    assert!(PrivateKey::from_bytes(&Scalar::from(10).to_repr()).is_ok());
    assert!(PrivateKey::from_bytes(&Scalar::from(100).to_repr()).is_ok());

    // Larger than the modulus
    assert!(PublicKey::from_bytes(&[255u8; 48]).is_err());
}
