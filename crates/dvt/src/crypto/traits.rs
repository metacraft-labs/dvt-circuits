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

impl<T> HexConvertible for T
where
    T: ByteConvertible,
    T::RawBytes: HexConvertible,
{
    fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
        let bytes = T::RawBytes::from_hex(hex).expect("Invalid hex string");
        Ok(T::from_bytes(&bytes).expect("Can't create object from hex string"))
    }

    fn to_hex(&self) -> String {
        self.to_bytes().to_hex()
    }
}
pub trait HexConvertible
where
    Self: Sized,
{
    fn from_hex(hex: &str) -> Result<Self, FromHexError>;
    fn to_hex(&self) -> String;
}

pub trait PublicKey: ByteConvertible + HexConvertible + Display + Debug {
    type Sig;

    fn verify_signature(&self, message: &[u8], signature: &Self::Sig) -> bool;
}

pub trait SecretKey: ByteConvertible + HexConvertible + Display + Debug {
    type PubKey;
    fn to_public_key(&self) -> Self::PubKey;
}

pub trait Signature: ByteConvertible + HexConvertible + Display + Debug {}

pub trait CryptoKeys where {
    type PubkeyRaw: HexConvertible + Clone + Serialize + for<'a> Deserialize<'a>;
    type Pubkey: PublicKey<Sig = Self::Signature> + ByteConvertible<RawBytes = Self::PubkeyRaw> + Clone;
    type SecretKey: SecretKey<PubKey = Self::Pubkey> + Clone;
    type Signature: Signature + Clone;
}
