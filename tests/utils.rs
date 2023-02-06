use bls::{
    key::PrivateKey,
    signature::{aggregate, hash, verify, Signature},
};
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

pub fn prepare_test_data(messages: Vec<&str>) -> (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut rng = ChaCha8Rng::seed_from_u64(12);

    let num_messages = messages.len();

    // generate private keys
    let private_keys: Vec<_> = (0..num_messages)
        .map(|_| PrivateKey::generate(&mut rng))
        .collect();

    let messages: Vec<Vec<u8>> = messages.iter().map(|s| s.as_bytes().to_vec()).collect();

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

    let aggregated_signature = aggregated_signature.to_uncompressed_bytes();
    let public_keys = public_keys
        .iter()
        .map(|key| key.to_uncompressed_bytes())
        .collect();

    (aggregated_signature, messages, public_keys)
}
