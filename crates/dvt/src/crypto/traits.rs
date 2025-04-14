use hex::FromHexError;

pub trait ByteConvertible {
    type Error;
    type RawBytes;

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

pub trait PublicKey: ByteConvertible + HexConvertable {
    type Sig;
    fn verify_signature(&self, message: &[u8], signature: &Self::Sig) -> bool;
}

pub trait SecretKey: ByteConvertible + HexConvertable {
    type PubKey;
    fn to_public_key(&self) -> Self::PubKey;
}

pub trait Signature: ByteConvertible + HexConvertable {}
