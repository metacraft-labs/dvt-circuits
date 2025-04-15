use std::fmt::{Debug, Display};

use hex::FromHexError;
use serde::{Deserialize, Serialize};

pub trait ByteConvertible {
    type Error: Debug;
    type RawBytes: Clone + Serialize + for<'a> Deserialize<'a>;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn from_bytes_safe(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn to_bytes(&self) -> Self::RawBytes;
}
pub trait HexConvertable
where
    Self: Sized,
{
    fn from_hex(hex: &str) -> Result<Self, FromHexError>;
    fn to_hex(&self) -> String;
}

pub trait PublicKey: ByteConvertible + HexConvertable + Display + Debug {
    type Sig;

    fn verify_signature(&self, message: &[u8], signature: &Self::Sig) -> bool;
}

pub trait SecretKey: ByteConvertible + HexConvertable + Display + Debug {
    type PubKey;
    fn to_public_key(&self) -> Self::PubKey;
}

pub trait Signature: ByteConvertible + HexConvertable + Display + Debug {}

pub trait CryptoKeys {
    type Pubkey: PublicKey<Sig = Self::Signature>;
    type SecretKey: SecretKey<PubKey = Self::Pubkey>;
    type Signature: Signature;
}
