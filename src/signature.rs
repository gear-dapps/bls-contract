/// Reworked copy from bls-signatures/src/key.rs
/// https://github.com/filecoin-project/bls-signatures
///
/// Removing dependency from std. Also remove code with feature "multicore"
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    Bls12, G1Affine, G2Affine, G2Projective, Gt, MillerLoopResult,
};
use gstd::Vec;
use pairing_lib::MultiMillerLoop;

use crate::error::Error;
use crate::key::*;

const CSUITE: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
const G2_COMPRESSED_SIZE: usize = 96;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Signature(G2Affine);

impl From<G2Projective> for Signature {
    fn from(val: G2Projective) -> Self {
        Signature(val.into())
    }
}
impl From<Signature> for G2Projective {
    fn from(val: Signature) -> Self {
        val.0.into()
    }
}

impl From<G2Affine> for Signature {
    fn from(val: G2Affine) -> Self {
        Signature(val)
    }
}

impl From<Signature> for G2Affine {
    fn from(val: Signature) -> Self {
        val.0
    }
}

impl Signature {
    pub fn from_bytes(raw: &[u8]) -> Result<Self, Error> {
        let g2 = g2_from_slice(raw)?;
        Ok(g2.into())
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.0.to_compressed().into_iter().collect()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_compressed().to_vec()
    }

    pub fn to_uncompressed_bytes(&self) -> Vec<u8> {
        self.0.to_uncompressed().to_vec()
    }

    pub fn from_uncompressed_bytes(raw: &[u8]) -> Result<Self, Error> {
        let mut array = [0u8; 192];
        for (i, byte) in array.iter_mut().enumerate() {
            *byte = raw[i];
        }
        let g2 = G2Affine::from_uncompressed(&array).unwrap();
        Ok(g2.into())
    }
}

pub fn g2_from_slice(raw: &[u8]) -> Result<G2Affine, Error> {
    if raw.len() != G2_COMPRESSED_SIZE {
        return Err(Error::SizeMismatch);
    }

    let mut res = [0u8; G2_COMPRESSED_SIZE];
    res.copy_from_slice(raw);

    Option::from(G2Affine::from_compressed(&res)).ok_or(Error::GroupDecode)
}

/// Hash the given message, as used in the signature.

pub fn hash(msg: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, CSUITE)
}

/// Aggregate signatures by multiplying them together.
/// Calculated by `signature = \sum_{i = 0}^n signature_i`.
pub fn aggregate(signatures: &[Signature]) -> Result<Signature, Error> {
    if signatures.is_empty() {
        return Err(Error::ZeroSizedInput);
    }

    let res = signatures
        .iter()
        .fold(G2Projective::identity(), |acc, signature| acc + signature.0);

    Ok(Signature(res.into()))
}

/// Verifies that the signature is the actual aggregated signature of hashes - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
pub fn verify(signature: &Signature, hashes: &[G2Projective], public_keys: &[PublicKey]) -> bool {
    if hashes.is_empty() || public_keys.is_empty() {
        return false;
    }

    let n_hashes = hashes.len();

    if n_hashes != public_keys.len() {
        return false;
    }

    // zero key & single hash should fail
    if n_hashes == 1 && public_keys[0].0.is_identity().into() {
        return false;
    }

    // Enforce that messages are distinct as a countermeasure against BLS's rogue-key attack.
    // See Section 3.1. of the IRTF's BLS signatures spec:
    // https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02#section-3.1
    for i in 0..(n_hashes - 1) {
        for j in (i + 1)..n_hashes {
            if hashes[i] == hashes[j] {
                return false;
            }
        }
    }

    let mut is_valid = true;

    let mut ml = public_keys
        .iter()
        .zip(hashes.iter())
        .map(|(pk, h)| {
            if pk.0.is_identity().into() {
                is_valid = false;
            }
            let pk = pk.as_affine();
            let h = G2Affine::from(h).into();
            Bls12::multi_miller_loop(&[(&pk, &h)])
        })
        .fold(MillerLoopResult::default(), |acc, cur| acc + cur);

    if !is_valid {
        return false;
    }

    let g1_neg = -G1Affine::generator();

    ml += Bls12::multi_miller_loop(&[(&g1_neg, &signature.0.into())]);

    ml.final_exponentiation() == Gt::identity()
}

/// Verifies that the signature is the actual aggregated signature of messages - pubkeys.
/// Calculated by `e(g1, signature) == \prod_{i = 0}^n e(pk_i, hash_i)`.
pub fn verify_messages(
    signature: &Signature,
    messages: &[&[u8]],
    public_keys: &[PublicKey],
) -> bool {
    let hashes: Vec<_> = messages
        .iter()
        .map(|msg| {
            let gas_available = gstd::exec::gas_available();
            gstd::debug!("before hash gas_available = {}", gas_available);
            let hash = hash(msg);
            gstd::debug!("after hash gas_available = {}", gstd::exec::gas_available());
            hash
        })
        .collect();

    let gas_available = gstd::exec::gas_available();
    gstd::debug!("before verify gas_available = {}", gas_available);
    let result = verify(signature, &hashes, public_keys);

    gstd::debug!(
        "after verify gas_available = {}",
        gstd::exec::gas_available()
    );

    result
}
