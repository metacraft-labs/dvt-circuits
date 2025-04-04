
pub trait PublicKey {
    // Associated type for the signature
    type Sig;
    // Associated type for errors
    type Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn to_hex(&self) -> String;

    fn verify_signature(&self, message: &[u8], signature: &Self::Sig) -> bool;
}


pub trait SecretKey {
    // Associated type for the signature
    type Sig;
    // Associated type for errors
    type Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn to_hex(&self) -> String;

    fn verify_signature(&self, message: &[u8], signature: &Self::Sig) -> bool;
}

pub trait Signature {
    type Error;

    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;

    fn to_hex(&self) -> String;

    

}
