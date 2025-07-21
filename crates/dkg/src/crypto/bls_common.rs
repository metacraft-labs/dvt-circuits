use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};

use core::convert::AsRef;

use crate::types::*;
use sha2::Sha256;

pub fn hash_message_to_g2(msg: &[u8]) -> G2Projective {
    let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    struct MsgInternal<'a> {
        msg: &'a [u8],
    }

    impl bls12_381::hash_to_curve::Message for MsgInternal<'_> {
        fn input_message(self, mut f: impl FnMut(&[u8])) {
            f(self.msg);
        }
    }
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(MsgInternal { msg }, domain)
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
    let key = bls_org::G1Affine::from_compressed(pubkey.as_ref());

    match key.into_option() {
        Some(key) => Ok(key.to_uncompressed()),
        None => Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid public key {}", pubkey),
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
            format!("Invalid public key {}", pubkey),
        ))),
    }
}

fn uncompress_bls_signature_slow(
    signature: &BLSSignatureRaw,
) -> Result<[u8; 192], Box<dyn std::error::Error>> {
    // We use the original bls library to verify the key
    // Becaus the sp1 library will crash if the key is invalid
    let key = bls_org::G2Affine::from_compressed(signature.as_ref());

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
    G1Affine::from_compressed(pubkey.as_ref())
        .into_option()
        .expect("G1 point is not torsion free.")
}

pub fn to_g1_projection(pubkey: &BLSPubkeyRaw) -> G1Projective {
    G1Projective::from(to_g1_affine(pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_message_to_g2_deterministic() {
        let msg = b"hello";
        let p1 = G2Affine::from(hash_message_to_g2(msg));
        let p2 = G2Affine::from(hash_message_to_g2(msg));
        assert_eq!(p1, p2);

        let p3 = G2Affine::from(hash_message_to_g2(b"world"));
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_bls_verify_precomputed_hash() {
        // Sample values taken from other tests
        let data = hex::decode("2f901d5cec8722e44afd59e94d0a56bf1506a72a0a60709920aad714d1a2ece0")
            .unwrap();
        let pk: BLSPubkeyRaw = hex::decode(
            "90346f9c5f3c09d96ea02acd0220daa8459f03866ed938c798e3716e42c7e033c9a7ef66a10f83af06d5c00b508c6d0f",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let sig: BLSSignatureRaw = hex::decode("a9c08eff13742f78f1e5929888f223b5b5b12b4836b5417c5a135cf24f4e2a4c66a6cdef91be3098b7e7a6a63903b61302e3cf2b8653101da245cf01a8d82b25debe7b18a3a2eb1778f8628fd2c59c8687f6e048a31250fbc2804c20043b8443")
            .unwrap()
            .try_into()
            .unwrap();

        let pk = G1Affine::from_compressed(&pk).into_option().unwrap();
        let sig = G2Affine::from_compressed(&sig).into_option().unwrap();
        let hashed = G2Affine::from(hash_message_to_g2(&data));

        assert!(bls_verify_precomputed_hash(&pk, &sig, &hashed));

        // wrong signature should fail
        let mut wrong_sig = sig;
        wrong_sig = G2Affine::from(hash_message_to_g2(b"bad"));
        assert!(!bls_verify_precomputed_hash(&pk, &wrong_sig, &hashed));
    }

    #[test]
    fn test_to_g1_affine_slow_errors() {
        let invalid: BLSPubkeyRaw = [0u8; BLS_PUBKEY_SIZE].into();
        assert!(to_g1_affine_slow(&invalid).is_err());

        let valid_bytes: BLSPubkeyRaw = hex::decode(
            "90346f9c5f3c09d96ea02acd0220daa8459f03866ed938c798e3716e42c7e033c9a7ef66a10f83af06d5c00b508c6d0f",
        )
        .unwrap()
        .try_into()
        .unwrap();
        let slow = to_g1_affine_slow(&valid_bytes).unwrap();
        let fast = to_g1_affine(&valid_bytes);
        assert_eq!(slow, fast);
    }

    #[test]
    fn test_to_g2_affine_slow_errors() {
        let invalid: BLSSignatureRaw = [0u8; BLS_SIGNATURE_SIZE].into();
        assert!(to_g2_affine_slow(&invalid).is_err());
    }
}
