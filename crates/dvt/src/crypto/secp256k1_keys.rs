use crate::crypto;
use std::fmt;

pub struct Secp256k1PublicKey {
    pub key: secp256k1::PublicKey,
}

type Secp256k1PublicKeyRaw = [u8; secp256k1::constants::PUBLIC_KEY_SIZE];

impl crypto::ByteConvertible for Secp256k1PublicKey {
    type Error = Box<dyn std::error::Error>;
    type RawBytes = Secp256k1PublicKeyRaw;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let key = secp256k1::PublicKey::from_slice(bytes)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        Ok(Self { key })
    }

    fn from_bytes_safe(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::from_bytes(bytes)
    }

    fn to_hex(&self) -> String {
        hex::encode(self.key.serialize())
    }

    fn to_bytes(&self) -> Self::RawBytes {
        self.key.serialize()
    }
}

impl fmt::Debug for Secp256k1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::crypto::ByteConvertible;
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Display for Secp256k1PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::crypto::ByteConvertible;
        write!(f, "{}", self.to_hex())
    }
}

impl crypto::PublicKey for Secp256k1PublicKey {
    type Sig = Secp256k1Signature;
    fn verify_signature(&self, message: &[u8], signature: &Self::Sig) -> bool {
        let secp = secp256k1::Secp256k1::verification_only();
        let msg_hash = match secp256k1::Message::from_digest_slice(message) {
            Ok(m) => m,
            Err(_) => return false,
        };
        secp.verify_ecdsa(&msg_hash, &signature.sig, &self.key)
            .is_ok()
    }
}

pub struct Secp256k1Signature {
    pub sig: secp256k1::ecdsa::Signature,
}

impl crypto::Signature for Secp256k1Signature {}
