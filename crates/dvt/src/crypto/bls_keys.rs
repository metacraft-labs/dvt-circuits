use crate::crypto::*;
use crate::types::*;
use bls12_381::{G1Affine, G2Affine, Scalar};
use std::fmt;

#[derive(PartialEq, Clone)]
pub struct BlsPublicKey {
    key: G1Affine,
}

impl traits::ByteConvertible for BlsPublicKey {
    type Error = Box<dyn std::error::Error>;
    type RawBytes = BLSPubkeyRaw;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::RawBytes: traits::HexConvertable,
    {
        let g1 = G1Affine::from_compressed(bytes).into_option();
        match g1 {
            Some(g1) => Ok(BlsPublicKey { key: g1 }),
            None => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid public key {}", bytes),
            ))),
        }
    }

    fn from_bytes_safe(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let g1 = to_g1_affine_slow(bytes)?;
        Ok(BlsPublicKey { key: g1 })
    }

    fn to_bytes(&self) -> Self::RawBytes {
        Self::RawBytes::from(self.key.to_compressed())
    }
}

impl HexConvertable for BlsPublicKey {
    fn to_hex(&self) -> String {
        self.to_bytes().to_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes: [u8; 48] = hex::decode(hex).unwrap().try_into().unwrap();
        let bytes = BLSPubkeyRaw::from(bytes);
        Ok(BlsPublicKey::from_bytes(&bytes).expect("Can't create BLS public key"))
    }
}

impl traits::PublicKey for BlsPublicKey {
    type Sig = BlsSignature;
    fn verify_signature(&self, message: &[u8], signature: &Self::Sig) -> bool {
        bls_verify(&self.key, &signature.sig, message)
    }
}

impl BlsPublicKey {
    pub fn from_g1(g1: &G1Affine) -> BlsPublicKey {
        BlsPublicKey { key: *g1 }
    }

    pub fn verify_signature_precomputed_hash(
        &self,
        hashed_msg: &G2Affine,
        signature: &BlsSignature,
    ) -> bool {
        bls_verify_precomputed_hash(&self.key, &signature.sig, hashed_msg)
    }

    pub fn equal(&self, g1: &G1Affine) -> bool {
        self.key == *g1
    }
}

impl fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_hex())
    }
}

#[derive(PartialEq, Clone)]
pub struct BlsSecretKey {
    key: Scalar,
}

impl traits::ByteConvertible for BlsSecretKey {
    type Error = Box<dyn std::error::Error>;
    type RawBytes = BLSSecretRaw;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut le_bytes: Self::RawBytes = *bytes;
        le_bytes.reverse();

        let sk = Scalar::from_bytes(&le_bytes);

        match sk.into_option() {
            Some(sk) => Ok(BlsSecretKey { key: sk }),
            None => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid secret key",
            ))),
        }
    }

    fn from_bytes_safe(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::RawBytes {
        let mut bytes = self.key.to_bytes();
        // Convert them to big-endian
        bytes.reverse();
        Self::RawBytes::from(bytes)
    }
}

impl HexConvertable for BlsSecretKey {
    fn to_hex(&self) -> String {
        self.to_bytes().to_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes: [u8; 32] = hex::decode(hex).unwrap().try_into().unwrap();
        let bytes = BLSSecretRaw::from(bytes);
        Ok(BlsSecretKey::from_bytes(&bytes).expect("Can't create BLS secret key"))
    }
}

impl traits::SecretKey for BlsSecretKey {
    type PubKey = BlsPublicKey;
    fn to_public_key(&self) -> Self::PubKey {
        BlsPublicKey {
            key: G1Affine::from(G1Affine::generator() * self.key),
        }
    }
}

impl fmt::Debug for BlsSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::crypto::ByteConvertible;
        write!(f, "SecretKey({})", self.to_bytes().to_hex())
    }
}

impl fmt::Display for BlsSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::crypto::ByteConvertible;
        write!(f, "SecretKey({})", self.to_bytes().to_hex())
    }
}

#[derive(PartialEq, Clone)]
pub struct BlsSignature {
    sig: G2Affine,
}

impl traits::Signature for BlsSignature {}

impl traits::ByteConvertible for BlsSignature {
    type Error = Box<dyn std::error::Error>;
    type RawBytes = BLSSignatureRaw;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let g2 = G2Affine::from_compressed(bytes).into_option();
        match g2 {
            Some(g2) => Ok(BlsSignature { sig: g2 }),
            None => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid signature",
            ))),
        }
    }

    fn from_bytes_safe(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let g2 = to_g2_affine_slow(bytes)?;
        Ok(BlsSignature { sig: g2 })
    }

    fn to_bytes(&self) -> Self::RawBytes {
        Self::RawBytes::from(self.sig.to_compressed())
    }
}

impl HexConvertable for BlsSignature {
    fn to_hex(&self) -> String {
        self.to_bytes().to_hex()
    }

    fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes: [u8; 96] = hex::decode(hex).unwrap().try_into().unwrap();
        let bytes = BLSSignatureRaw::from(bytes);
        Ok(BlsSignature::from_bytes(&bytes).expect("Can't create BLS signature"))
    }
}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

impl fmt::Display for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

#[derive(Clone)]
pub struct BlsCrypto {}

impl CryptoKeys for BlsCrypto {
    type Pubkey = BlsPublicKey;
    type SecretKey = BlsSecretKey;
    type Signature = BlsSignature;
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_bls_id_from_u32() {
        let mut bytes: [u8; 32] = [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];
        assert_eq!(bls_id_from_u32(0), Scalar::from_bytes(&bytes).unwrap());
        bytes[0] = 1;
        assert_eq!(bls_id_from_u32(1), Scalar::from_bytes(&bytes).unwrap());
        bytes[0] = 2;
        assert_eq!(bls_id_from_u32(2), Scalar::from_bytes(&bytes).unwrap());
    }

    #[test]
    fn test_bls_id_from_u32_to_hex() {
        let id = bls_id_from_u32(0);
        assert_eq!(
            hex::encode(id.to_bytes()),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        let id = bls_id_from_u32(1);
        assert_eq!(
            hex::encode(id.to_bytes()),
            "0100000000000000000000000000000000000000000000000000000000000000"
        );
        let id = bls_id_from_u32(2);
        assert_eq!(
            hex::encode(id.to_bytes()),
            "0200000000000000000000000000000000000000000000000000000000000000"
        )
    }
}
