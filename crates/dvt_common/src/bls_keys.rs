use std::fmt;

use bls12_381::{G1Affine, G2Affine, Scalar};

use crate::bls_common::*;

#[derive(PartialEq)]
pub struct PublicKey {
    key: G1Affine,
}

impl PublicKey {
    pub fn to_hex(&self) -> String {
        hex::encode(self.key.to_compressed())
    }

    pub fn from_bytes(bytes: &dvt_abi::BLSPubkey) -> Result<PublicKey, Box<dyn std::error::Error>> {
        let g1 = G1Affine::from_compressed(&bytes).into_option();
        match g1 {
            Some(g1) => Ok(PublicKey { key: g1 }),
            None => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid public key {}", hex::encode(&bytes)),
            ))),
        }
    }

    pub fn from_bytes_safe(
        bytes: &dvt_abi::BLSPubkey,
    ) -> Result<PublicKey, Box<dyn std::error::Error>> {
        let g1 = to_g1_affine_slow(bytes)?;
        Ok(PublicKey { key: g1 })
    }

    pub fn from_g1(g1: &G1Affine) -> PublicKey {
        PublicKey { key: *g1 }
    }

    pub fn verify_signature(&self, message: &[u8], signature: &Signature) -> bool {
        bls_verify(&self.key, &signature.sig, message)
    }

    pub fn verify_signature_precomputed_hash(
        &self,
        hashed_msg: &G2Affine,
        signature: &Signature,
    ) -> bool {
        bls_verify_precomputed_hash(&self.key, &signature.sig, hashed_msg)
    }

    pub fn eq(&self, g1: &G1Affine) -> bool {
        self.key == *g1
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

#[derive(PartialEq)]
pub struct SecretKey {
    key: Scalar,
}

impl SecretKey {
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            key: G1Affine::from(G1Affine::generator() * self.key),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<SecretKey, Box<dyn std::error::Error>> {
        let mut le_bytes = bytes.clone();
        le_bytes.reverse();

        let sk = Scalar::from_bytes(&le_bytes);

        match sk.into_option() {
            Some(sk) => Ok(SecretKey { key: sk }),
            None => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid secret key",
            ))),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = self.key.to_bytes();
        // Convert them to big-endian
        bytes.reverse();
        return bytes;
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({})", hex::encode(self.to_bytes()))
    }
}

impl fmt::Display for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey({})", hex::encode(self.to_bytes()))
    }
}

#[derive(PartialEq)]
pub struct Signature {
    sig: G2Affine,
}

impl Signature {
    pub fn to_hex(&self) -> String {
        hex::encode(self.sig.to_compressed())
    }

    pub fn from_bytes(
        bytes: &dvt_abi::BLSSignature,
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        let g2 = G2Affine::from_compressed(&bytes).into_option();
        match g2 {
            Some(g2) => Ok(Signature { sig: g2 }),
            None => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid signature",
            ))),
        }
    }

    pub fn from_bytes_safe(
        bytes: &dvt_abi::BLSSignature,
    ) -> Result<Signature, Box<dyn std::error::Error>> {
        let g2 = to_g2_affine_slow(bytes)?;
        Ok(Signature { sig: g2 })
    }

    pub fn from_g2(g2: &G2Affine) -> Signature {
        Signature { sig: *g2 }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}
