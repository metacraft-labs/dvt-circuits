use crate::bls_common::*;
use crate::crypto;
use crate::HexConvertable;
use bls12_381::{G1Affine, G2Affine, Scalar};
use std::fmt;

pub const BLS_SIGNATURE_SIZE: usize = 96;
pub const BLS_PUBKEY_SIZE: usize = 48;
pub const BLS_SECRET_SIZE: usize = 32;
pub const BLS_ID_SIZE: usize = 32;
pub const GEN_ID_SIZE: usize = 16;
pub const SHA256_SIZE: usize = 32;

pub trait AsByteArr {
    fn as_arr(&self) -> &[u8];
}

macro_rules! define_raw_type {
    ($name:ident, $size_const:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub [u8; $size_const]);

        impl std::ops::Deref for $name {
            type Target = [u8; $size_const];
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl std::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl AsRef<[u8; $size_const]> for $name {
            fn as_ref(&self) -> &[u8; $size_const] {
                &self.0
            }
        }

        impl AsMut<[u8; $size_const]> for $name {
            fn as_mut(&mut self) -> &mut [u8; $size_const] {
                &mut self.0
            }
        }

        impl From<[u8; $size_const]> for $name {
            fn from(bytes: [u8; $size_const]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; $size_const] {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl AsByteArr for $name {
            fn as_arr(&self) -> &[u8] {
                &self.0
            }
        }

        impl std::convert::TryFrom<&[u8]> for $name {
            type Error = std::array::TryFromSliceError;
            fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
                Ok(Self(slice.try_into()?))
            }
        }

        impl std::convert::TryFrom<Vec<u8>> for $name {
            type Error = std::array::TryFromSliceError;
            fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
                let array: [u8; $size_const] = vec.as_slice().try_into()?;
                Ok(Self(array))
            }
        }

        impl std::cmp::PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(&other.0)
            }
        }

        impl std::cmp::Ord for $name {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl crypto::HexConvertable for $name {
            fn from_hex(hex: &String) -> Result<Self, hex::FromHexError> {
                let bytes: [u8; $size_const] = hex::decode(hex)?.try_into().unwrap();
                Ok(Self(bytes))
            }

            fn to_hex(&self) -> String {
                hex::encode(&self.0)
            }
        }
    };
}

#[macro_export]
macro_rules! for_each_raw_type {
    ($macro:ident) => {
        $macro!(BLSPubkeyRaw, BLS_PUBKEY_SIZE);
        $macro!(BLSSecretRaw, BLS_SECRET_SIZE);
        $macro!(BLSIdRaw, BLS_ID_SIZE);
        $macro!(BLSSignatureRaw, BLS_SIGNATURE_SIZE);
        $macro!(SHA256Raw, SHA256_SIZE);
    };
}

for_each_raw_type!(define_raw_type);

#[derive(PartialEq)]
pub struct BlsPublicKey {
    key: G1Affine,
}

impl crypto::ByteConvertible for BlsPublicKey {
    type Error = Box<dyn std::error::Error>;
    type RawBytes = BLSPubkeyRaw;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::RawBytes: HexConvertable,
    {
        let g1 = G1Affine::from_compressed(bytes).into_option();
        match g1 {
            Some(g1) => Ok(BlsPublicKey { key: g1 }),
            None => Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid public key {}", bytes.to_hex()),
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

    fn to_hex(&self) -> String {
        hex::encode(self.key.to_compressed())
    }

    fn to_bytes(&self) -> Self::RawBytes {
        Self::RawBytes::from(self.key.to_compressed())
    }
}

impl crypto::PublicKey for BlsPublicKey {
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
        use crate::crypto::ByteConvertible;
        write!(f, "PublicKey({})", self.to_hex())
    }
}

impl fmt::Display for BlsPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::crypto::ByteConvertible;
        write!(f, "PublicKey({})", self.to_hex())
    }
}

#[derive(PartialEq)]
pub struct BlsSecretKey {
    key: Scalar,
}

impl crypto::ByteConvertible for BlsSecretKey {
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

    fn to_hex(&self) -> String {
        self.to_bytes().to_hex()
    }
}

impl crypto::Signature for BlsSignature {}

impl crypto::SecretKey for BlsSecretKey {
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

#[derive(PartialEq)]
pub struct BlsSignature {
    sig: G2Affine,
}

impl crypto::ByteConvertible for BlsSignature {
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

    fn to_hex(&self) -> String {
        hex::encode(self.sig.to_compressed())
    }
}

impl fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::crypto::ByteConvertible;
        write!(f, "Signature({})", self.to_hex())
    }
}

impl fmt::Display for BlsSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::crypto::ByteConvertible;
        write!(f, "Signature({})", self.to_hex())
    }
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
