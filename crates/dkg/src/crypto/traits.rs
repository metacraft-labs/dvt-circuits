use std::fmt::{Debug, Display};

use hex::FromHexError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub trait AsByteArr {
    fn as_arr(&self) -> &[u8];
}

pub trait ByteConvertible {
    type Error: Debug + Display;
    type RawBytes: Clone
        + Serialize
        + for<'a> Deserialize<'a>
        + AsByteArr
        + Display
        + PartialEq
        + JsonSchema
        + for<'a> TryFrom<&'a [u8]>;

    fn from_bytes(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn from_bytes_safe(bytes: &Self::RawBytes) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn to_bytes(&self) -> Self::RawBytes;
}

pub type RawBytes<T> = <T as ByteConvertible>::RawBytes;

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
    type MessageMapping;

    fn verify_signature(&self, message: &[u8], signature: &Self::Sig) -> bool;

    fn verify_signature_from_precomputed_mapping(
        &self,
        msg: &Self::MessageMapping,
        signature: &Self::Sig,
    ) -> bool;
}

pub trait SecretKey: ByteConvertible + HexConvertible + Display + Debug {
    type PubKey: PublicKey;
    fn to_public_key(&self) -> Self::PubKey;
}

pub trait Signature: ByteConvertible + HexConvertible + Display + Debug {}

pub trait TScalar: Clone + Copy + ByteConvertible {
    fn mul(self, other: &Self) -> Self;
    fn mul_assign(&mut self, other: &Self) {
        *self = self.mul(other);
    }
    fn sub(self, other: &Self) -> Self;
    fn is_zero(self) -> bool;
    fn invert(self) -> Self;
    fn from_u32(x: u32) -> Self;
}

pub trait TPoint: Clone + Copy + ByteConvertible {
    type Scalar: TScalar;
    fn identity() -> Self;

    fn add(self, other: &Self) -> Self;
    fn mul_scalar(self, other: &Self::Scalar) -> Self;
}

pub trait Curve {
    type Scalar: TScalar + Display;
    type Point: TPoint<Scalar = Self::Scalar> + PartialEq + Display;
}

pub trait CryptoKeys {
    type PubkeyRaw: HexConvertible
        + Clone
        + Serialize
        + for<'a> Deserialize<'a>
        + Display
        + AsByteArr
        + JsonSchema
        + for<'a> TryFrom<&'a [u8]>;

    type SecretKeyRaw: HexConvertible
        + Clone
        + Serialize
        + for<'a> Deserialize<'a>
        + Display
        + AsByteArr
        + JsonSchema
        + for<'a> TryFrom<&'a [u8]>;

    type Pubkey: PublicKey<Sig = Self::Signature, MessageMapping = Self::MessageMapping>
        + ByteConvertible<RawBytes = Self::PubkeyRaw>
        + Clone;
    type SecretKey: SecretKey<PubKey = Self::Pubkey>
        + ByteConvertible<RawBytes = Self::SecretKeyRaw>
        + Clone;
    type Signature: Signature + Clone;
    type MessageMapping;

    fn precompute_message_mapping(msg: &[u8]) -> Self::MessageMapping;
}

/// Helper types to reduce over usage of 'SomeType as SomeTrait'
type PubKey<T> = <T as CryptoKeys>::Pubkey;
type SecKey<T> = <T as CryptoKeys>::SecretKey;
type Sig<T> = <T as CryptoKeys>::Signature;

/// Core trait defining the cryptographic configuration for a DKG (Distributed Key Generation) setup.
///
/// This trait specifies the types of cryptographic components used for:
/// - threshold signing
/// - identity authentication
/// - the underlying curve math used for DKG computations.
pub trait DkgSetup: Clone {
    /// Cryptographic scheme used for threshold signing and DKG key generation.
    ///
    /// The `PubkeyRaw` type must match the raw bytes of the curve point used in this setup.
    type TargetCryptography: CryptoKeys<
            PubkeyRaw = RawBytes<<Self::CCurve as Curve>::Point>,
            SecretKeyRaw = RawBytes<<Self::CCurve as Curve>::Scalar>,
        > + Clone;

    /// Cryptographic scheme used for identity and authentication.
    ///
    /// This may be different from `TargetCryptography` and used
    /// to verify commitment signatures.
    type IdentityCryptography: CryptoKeys + Clone;

    /// The elliptic curve (or equivalent math) used by `TargetCryptography`
    /// to perform polynomial evaluation and threshold operations (e.g. Shamir secret sharing).
    type CCurve: Curve + Clone;
}

/// Helper trait to reduce boilerplate when working with generic `DkgSetup`-based types.
///
/// This trait abstracts away verbose associated type expressions like:
/// `<SomeType as SomeTrait>::AssociatedType`,
/// making generic code more readable and maintainable.
///
/// It captures common aliases used throughout DKG-related cryptographic logic.
pub trait DkgSetupTypes<T: DkgSetup>
where
    Self::Point: ByteConvertible<RawBytes = RawBytes<PubKey<T::TargetCryptography>>>,
    Self::Scalar: ByteConvertible<RawBytes = RawBytes<SecKey<T::TargetCryptography>>>,
    RawBytes<PubKey<T::IdentityCryptography>>: JsonSchema,
    RawBytes<<T::IdentityCryptography as CryptoKeys>::Signature>: JsonSchema,
{
    type Point: TPoint<Scalar = Self::Scalar> + Clone + Display + PartialEq;
    type Scalar: TScalar + Clone + Display;
    type Curve: Curve<Point = Self::Point, Scalar = Self::Scalar> + Clone;
    type DkgSecretKey: SecretKey<PubKey = Self::DkgPubkey>
        + ByteConvertible<RawBytes = RawBytes<Self::Scalar>>
        + Clone;
    type DkgPubkey: PublicKey<
            Sig = Self::DkgSignature,
            MessageMapping = <T::TargetCryptography as CryptoKeys>::MessageMapping,
        > + ByteConvertible<RawBytes = RawBytes<Self::Point>>
        + Clone;
    type DkgSignature: Signature
        + ByteConvertible<RawBytes = RawBytes<Sig<T::TargetCryptography>>>
        + Clone;

    type CommitmentPubkey: PublicKey<Sig = Self::CommitmentSignature>
        + ByteConvertible<
            RawBytes = RawBytes<PubKey<T::IdentityCryptography>>,
            Error = <PubKey<T::IdentityCryptography> as ByteConvertible>::Error,
        > + Clone;
    type CommitmentSignature: Signature
        + ByteConvertible<
            RawBytes = RawBytes<Sig<T::IdentityCryptography>>,
            Error = <Sig<T::IdentityCryptography> as ByteConvertible>::Error,
        > + Clone;
}

impl<T: DkgSetup> DkgSetupTypes<T> for T {
    type Point = <Self::Curve as Curve>::Point;
    type Scalar = <Self::Curve as Curve>::Scalar;
    type Curve = T::CCurve;
    type DkgPubkey = PubKey<T::TargetCryptography>;
    type DkgSignature = Sig<T::TargetCryptography>;
    type DkgSecretKey = SecKey<T::TargetCryptography>;
    type CommitmentPubkey = PubKey<T::IdentityCryptography>;
    type CommitmentSignature = Sig<T::IdentityCryptography>;
}
