use crate::crypto;
use std::fmt;

use super::{CryptoKeys, HexConvertible, RawBytes};
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
    type PubkeyRaw = RawBytes<Secp256k1PublicKey>;
    type SecretKeyRaw = RawBytes<Secp256k1SecretKey>;
    type SecretKey = Secp256k1SecretKey;
    type Signature = Secp256k1Signature;
    type MessageMapping = Vec<u8>;

    fn precompute_message_mapping(msg: &[u8]) -> Self::MessageMapping {
        msg.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::traits::ByteConvertible;
    use crate::*;
    #[test]
    fn test_secp256k1_public_key_from_bytes_error() {
        let invalid: SECP256K1PubkeyRaw = [0u8; SECP256K1_PUBKEY_SIZE].into();
        assert!(Secp256k1PublicKey::from_bytes(&invalid).is_err());
    }

    #[test]
    fn test_secp256k1_secret_key_from_bytes_error() {
        let invalid: SECP256K1SecretRaw = [0u8; SECP256K1_SECRET_SIZE].into();
        assert!(Secp256k1SecretKey::from_bytes(&invalid).is_err());
    }

    #[test]
    fn test_verify_signature_invalid_message_len() {
        let sk_bytes: [u8; 32] = [1u8; 32];
        let sk = Secp256k1SecretKey::from_bytes(&crate::types::SECP256K1SecretRaw::from(sk_bytes))
            .unwrap();
        let pk = sk.to_public_key();

        let secp = secp256k1::Secp256k1::new();
        let msg = [2u8; 32];
        let m = secp256k1::Message::from_digest_slice(&msg).unwrap();
        let sig = secp.sign_ecdsa(&m, &sk.secret);
        let sig = Secp256k1Signature { sig };

        // message that's not 32 bytes should fail
        let bad_msg = [1u8; 31];
        assert!(!pk.verify_signature(&bad_msg, &sig));
    }

    #[test]
    fn test_secp256k1_roundtrip_and_sign() {
        let sk_bytes: [u8; 32] = [1u8; 32];
        let raw_sk = crate::types::SECP256K1SecretRaw::from(sk_bytes);
        let sk = Secp256k1SecretKey::from_bytes(&raw_sk).unwrap();
        let pk = sk.to_public_key();

        let raw_pk = pk.to_bytes();
        let decoded_pk = Secp256k1PublicKey::from_bytes(&raw_pk).unwrap();
        assert_eq!(decoded_pk.to_bytes(), raw_pk);

        // sign a hashed message
        let msg = [2u8; 32];
        let secp = secp256k1::Secp256k1::new();
        let m = secp256k1::Message::from_digest_slice(&msg).unwrap();
        let sig = secp.sign_ecdsa(&m, &sk.secret);
        let sig = Secp256k1Signature { sig };

        assert!(pk.verify_signature(&msg, &sig));

        // wrong message fails
        let bad_msg = [3u8; 32];
        assert!(!pk.verify_signature(&bad_msg, &sig));
    }
}
