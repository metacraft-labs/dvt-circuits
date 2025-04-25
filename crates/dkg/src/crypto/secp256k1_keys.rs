use crate::crypto;
use std::fmt;

use super::{ByteConvertible, CryptoKeys, HexConvertible};

#[derive(PartialEq, Clone)]
pub struct Secp256k1PublicKey {
    pub key: secp256k1::PublicKey,
}

impl crypto::ByteConvertible for Secp256k1PublicKey {
    type Error = Box<dyn std::error::Error>;
    type RawBytes = crate::types::SECP256K1PubkeyRaw;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let key = secp256k1::PublicKey::from_slice(bytes.as_ref())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(Self { key })
    }

    fn from_bytes_safe(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::RawBytes {
        Self::RawBytes::from(self.key.serialize())
    }
}

impl fmt::Debug for Secp256k1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for Secp256k1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl crypto::PublicKey for Secp256k1PublicKey {
    type Sig = Secp256k1Signature;
    type MessageMapping = Vec<u8>;

    fn verify_signature(&self, message: &[u8], signature: &Self::Sig) -> bool {
        let secp = secp256k1::Secp256k1::verification_only();
        let msg_hash = match secp256k1::Message::from_digest_slice(message) {
            Ok(m) => m,
            Err(_) => return false,
        };
        println!("msg_hash: {}", msg_hash);
        println!("signature: {}", signature);
        println!("key: {}", self.key);
        match secp.verify_ecdsa(&msg_hash, &signature.sig, &self.key) {
            Ok(_) => true,
            Err(e) => {
                println!("Failed to verify signature: {}", e);
                false
            }
        }
    }

    fn verify_signature_from_precomputed_mapping(
        &self,
        msg: &Self::MessageMapping,
        signature: &Self::Sig,
    ) -> bool {
        self.verify_signature(msg, signature)
    }
}

#[derive(PartialEq, Clone)]
pub struct Secp256k1SecretKey {
    pub secret: secp256k1::SecretKey,
}

impl crypto::ByteConvertible for Secp256k1SecretKey {
    type Error = Box<dyn std::error::Error>;
    type RawBytes = crate::types::SECP256K1SecretRaw;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let secret = secp256k1::SecretKey::from_slice(bytes.as_ref())
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(Secp256k1SecretKey { secret })
    }

    fn from_bytes_safe(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::RawBytes {
        Self::RawBytes::from(self.secret.secret_bytes())
    }
}

impl crate::traits::SecretKey for Secp256k1SecretKey {
    type PubKey = Secp256k1PublicKey;

    fn to_public_key(&self) -> Self::PubKey {
        let spec = secp256k1::Secp256k1::new();
        let pubkey = self.secret.public_key(&spec);
        Secp256k1PublicKey { key: pubkey }
    }
}

impl fmt::Debug for Secp256k1SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for Secp256k1SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

#[derive(PartialEq, Clone)]
pub struct Secp256k1Signature {
    pub sig: secp256k1::ecdsa::Signature,
}

impl crypto::Signature for Secp256k1Signature {}

impl fmt::Debug for Secp256k1Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for Secp256k1Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl crypto::ByteConvertible for Secp256k1Signature {
    type Error = Box<dyn std::error::Error>;
    type RawBytes = crate::types::SECP256K1SignatureRaw;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let sig = secp256k1::ecdsa::Signature::from_compact(bytes.as_ref())?;
        Ok(Secp256k1Signature { sig })
    }

    fn from_bytes_safe(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::from_bytes(bytes)
    }

    fn to_bytes(&self) -> Self::RawBytes {
        Self::RawBytes::from(self.sig.serialize_compact())
    }
}

#[derive(Clone)]
pub struct Secp256k1Crypto {}

impl CryptoKeys for Secp256k1Crypto {
    type Pubkey = Secp256k1PublicKey;
    type PubkeyRaw = <Secp256k1PublicKey as ByteConvertible>::RawBytes;
    type SecretKey = Secp256k1SecretKey;
    type Signature = Secp256k1Signature;
    type MessageMapping = Vec<u8>;

    fn precompute_message_mapping(msg: &[u8]) -> Self::MessageMapping {
        msg.to_vec()
    }
}
