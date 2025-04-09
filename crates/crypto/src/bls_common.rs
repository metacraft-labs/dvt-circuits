use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};

use crate::bls_keys::*;
use sha2::Sha256;

pub fn hash_message_to_g2(msg: &[u8]) -> G2Projective {
    let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(msg, domain)
}

pub fn bls_verify_precomputed_hash(
    pubkey: &G1Affine,
    signature: &G2Affine,
    hashed_msg: &G2Affine,
) -> bool {
    let left = pairing(pubkey, hashed_msg);
    let right = pairing(&G1Affine::generator(), signature);

    left == right
}
pub fn bls_verify(pubkey: &G1Affine, signature: &G2Affine, message: &[u8]) -> bool {
    let hashed_msg = hash_message_to_g2(message);
    let msg_affine = G2Affine::from(hashed_msg);
    bls_verify_precomputed_hash(pubkey, signature, &msg_affine)
}

pub fn bls_id_from_u32(id: u32) -> Scalar {
    let unwrapped_le: [u8; 4] = id.to_le_bytes();
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&unwrapped_le);
    Scalar::from_bytes(&bytes).expect("Invalid id")
}

fn uncompress_bls_pubkey_slow(
    pubkey: &BLSPubkeyRaw,
) -> Result<[u8; 96], Box<dyn std::error::Error>> {
    // We use the original bls library to verify the key
    // Becaus the sp1 library will crash if the key is invalid
    let key = bls_org::G1Affine::from_compressed(pubkey);

    match key.into_option() {
        Some(key) => Ok(key.to_uncompressed()),
        None => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid public key {}", hex::encode(pubkey)),
        ))),
    }
}

pub fn to_g1_affine_slow(pubkey: &BLSPubkeyRaw) -> Result<G1Affine, Box<dyn std::error::Error>> {
    let bytes = uncompress_bls_pubkey_slow(pubkey)?;

    let key = G1Affine::from_uncompressed(&bytes);
    match key.into_option() {
        Some(key) => Ok(key),
        None => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid public key {}", hex::encode(pubkey)),
        ))),
    }
}

fn uncompress_bls_signature_slow(
    signature: &BLSSignatureRaw,
) -> Result<[u8; 192], Box<dyn std::error::Error>> {
    // We use the original bls library to verify the key
    // Becaus the sp1 library will crash if the key is invalid
    let key = bls_org::G2Affine::from_compressed(signature);

    match key.into_option() {
        Some(key) => Ok(key.to_uncompressed()),
        None => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid signature",
        ))),
    }
}
pub fn to_g2_affine_slow(
    signature: &BLSSignatureRaw,
) -> Result<G2Affine, Box<dyn std::error::Error>> {
    let bytes = uncompress_bls_signature_slow(signature)?;

    let key = G2Affine::from_uncompressed(&bytes);
    match key.into_option() {
        Some(key) => Ok(key),
        None => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid signature",
        ))),
    }
}

pub fn to_g1_affine(pubkey: &BLSPubkeyRaw) -> G1Affine {
    G1Affine::from_compressed(pubkey)
        .into_option()
        .expect("G1 point is not torsion free.")
}

pub fn to_g1_projection(pubkey: &BLSPubkeyRaw) -> G1Projective {
    G1Projective::from(to_g1_affine(pubkey))
}
