use base64::STANDARD;
use base64_serde::base64_serde_type;
use bls::{
    error::Error,
    key::{PrivateKey, PublicKey},
    signature::{aggregate, g2_from_slice, hash, verify, verify_messages, Signature},
};
use gstd::String;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::Deserialize;

use bls::key::G1_COMPRESSED_SIZE;

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G1Affine, G1Projective, G2Projective, Scalar,
};

const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[test]
fn basic_aggregation() {
    let mut rng = ChaCha8Rng::seed_from_u64(12);

    let num_messages = 10;

    // generate private keys
    let private_keys: Vec<_> = (0..num_messages)
        .map(|_| PrivateKey::generate(&mut rng))
        .collect();

    // generate messages
    let messages: Vec<Vec<u8>> = (0..num_messages)
        .map(|_| (0..64).map(|_| rng.gen()).collect())
        .collect();

    // sign messages
    let sigs = messages
        .iter()
        .zip(&private_keys)
        .map(|(message, pk)| pk.sign(message))
        .collect::<Vec<Signature>>();

    let aggregated_signature = aggregate(&sigs).expect("failed to aggregate");

    let hashes = messages
        .iter()
        .map(|message| hash(message))
        .collect::<Vec<_>>();
    let public_keys = private_keys
        .iter()
        .map(|pk| pk.public_key())
        .collect::<Vec<_>>();

    assert!(
        verify(&aggregated_signature, &hashes, &public_keys),
        "failed to verify"
    );

    let messages = messages.iter().map(|r| &r[..]).collect::<Vec<_>>();
    assert!(verify_messages(
        &aggregated_signature,
        &messages[..],
        &public_keys
    ));
}

#[test]
fn aggregation_same_messages() {
    let mut rng = ChaCha8Rng::seed_from_u64(12);

    let num_messages = 10;

    // generate private keys
    let private_keys: Vec<_> = (0..num_messages)
        .map(|_| PrivateKey::generate(&mut rng))
        .collect();

    // generate messages
    let message: Vec<u8> = (0..64).map(|_| rng.gen()).collect();

    // sign messages
    let sigs = private_keys
        .iter()
        .map(|pk| pk.sign(&message))
        .collect::<Vec<Signature>>();

    let aggregated_signature = aggregate(&sigs).expect("failed to aggregate");

    // check that equal messages can not be aggreagated
    let hashes: Vec<_> = (0..num_messages).map(|_| hash(&message)).collect();
    let public_keys = private_keys
        .iter()
        .map(|pk| pk.public_key())
        .collect::<Vec<_>>();
    assert!(
        !verify(&aggregated_signature, &hashes, &public_keys),
        "must not verify aggregate with the same messages"
    );
    let messages = vec![&message[..]; num_messages];

    assert!(!verify_messages(
        &aggregated_signature,
        &messages[..],
        &public_keys
    ));
}

#[test]
fn test_zero_key() {
    let mut rng = ChaCha8Rng::seed_from_u64(12);

    // In the current iteration we expect the zero key to be valid and work.
    let zero_key: PrivateKey = Scalar::zero().into();
    assert!(bool::from(zero_key.public_key().0.is_identity()));

    println!(
        "{:?}\n{:?}",
        zero_key.public_key().as_bytes(),
        zero_key.as_bytes()
    );
    let num_messages = 10;

    // generate private keys
    let mut private_keys: Vec<_> = (0..num_messages - 1)
        .map(|_| PrivateKey::generate(&mut rng))
        .collect();

    private_keys.push(zero_key);

    // generate messages
    let messages: Vec<Vec<u8>> = (0..num_messages)
        .map(|_| (0..64).map(|_| rng.gen()).collect())
        .collect();

    // sign messages
    let sigs = messages
        .iter()
        .zip(&private_keys)
        .map(|(message, pk)| pk.sign(message))
        .collect::<Vec<Signature>>();

    let aggregated_signature = aggregate(&sigs).expect("failed to aggregate");

    let hashes = messages
        .iter()
        .map(|message| hash(message))
        .collect::<Vec<_>>();
    let public_keys = private_keys
        .iter()
        .map(|pk| pk.public_key())
        .collect::<Vec<_>>();

    assert!(
        !verify(&aggregated_signature, &hashes, &public_keys),
        "verified with zero key"
    );

    let messages = messages.iter().map(|r| &r[..]).collect::<Vec<_>>();
    assert!(!verify_messages(
        &aggregated_signature,
        &messages[..],
        &public_keys
    ));

    // single message is rejected
    let signature = zero_key.sign(messages[0]);

    assert!(!zero_key.public_key().verify(signature, messages[0]));

    let aggregated_signature = aggregate(&[signature][..]).expect("failed to aggregate");
    assert!(!verify_messages(
        &aggregated_signature,
        &messages[..1],
        &[zero_key.public_key()][..],
    ));
}

#[test]
fn test_bytes_roundtrip() {
    let mut rng = ChaCha8Rng::seed_from_u64(12);
    let sk = PrivateKey::generate(&mut rng);

    let msg = (0..64).map(|_| rng.gen()).collect::<Vec<u8>>();
    let signature = sk.sign(msg);

    let signature_bytes = signature.as_bytes();
    assert_eq!(signature_bytes.len(), 96);
    assert_eq!(Signature::from_bytes(&signature_bytes).unwrap(), signature);
}

base64_serde_type!(Base64Standard, STANDARD);

#[derive(Debug, Clone, Deserialize)]
struct Case {
    #[serde(rename = "Msg")]
    msg: String,
    #[serde(rename = "Ciphersuite")]
    ciphersuite: String,
    #[serde(rename = "G1Compressed", with = "Base64Standard")]
    g1_compressed: Vec<u8>,
    #[serde(rename = "G2Compressed", with = "Base64Standard")]
    g2_compressed: Vec<u8>,
    #[serde(rename = "BLSPrivKey")]
    priv_key: Option<String>,
    #[serde(rename = "BLSPubKey")]
    pub_key: Option<String>,
    #[serde(rename = "BLSSigG2")]
    signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Cases {
    cases: Vec<Case>,
}

fn g1_from_slice(raw: &[u8]) -> Result<G1Affine, Error> {
    if raw.len() != G1_COMPRESSED_SIZE {
        return Err(Error::SizeMismatch);
    }

    let mut res = [0u8; G1_COMPRESSED_SIZE];
    res.as_mut().copy_from_slice(raw);

    Option::from(G1Affine::from_compressed(&res)).ok_or(Error::GroupDecode)
}

fn hash_to_g1(msg: &[u8], suite: &[u8]) -> G1Projective {
    <G1Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, suite)
}

fn hash_to_g2(msg: &[u8], suite: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, suite)
}

#[test]
fn test_vectors() {
    let cases: Cases =
        serde_json::from_slice(&std::fs::read("./tests/data.json").unwrap()).unwrap();

    for case in cases.cases {
        let g1: G1Projective = g1_from_slice(&case.g1_compressed).unwrap().into();

        assert_eq!(
            g1,
            hash_to_g1(case.msg.as_bytes(), case.ciphersuite.as_bytes())
        );

        let g2: G2Projective = g2_from_slice(&case.g2_compressed).unwrap().into();
        assert_eq!(
            g2,
            hash_to_g2(case.msg.as_bytes(), case.ciphersuite.as_bytes())
        );

        if case.ciphersuite.as_bytes() == CSUITE {
            let pub_key =
                PublicKey::from_bytes(&base64::decode(case.pub_key.as_ref().unwrap()).unwrap())
                    .unwrap();
            let priv_key = PrivateKey::from_string(case.priv_key.as_ref().unwrap()).unwrap();
            let signature =
                Signature::from_bytes(&base64::decode(case.signature.as_ref().unwrap()).unwrap())
                    .unwrap();

            let sig2 = priv_key.sign(&case.msg);
            assert_eq!(signature, sig2, "signatures do not match");

            assert!(pub_key.verify(signature, &case.msg), "failed to verify");
        }
    }
}
