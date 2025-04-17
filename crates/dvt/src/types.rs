use crate::{dvt_math, traits, BlsCrypto, ByteConvertible, CryptoKeys, HexConvertible};
use group::Curve;
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

pub trait DvtSetup: Clone {
    type GenCrypto: CryptoKeys<PubkeyRaw = <<Self::Curve as crate::dvt_math::Curve>::Point as ByteConvertible>::RawBytes> + Clone;
    type CommitmentCrypto: CryptoKeys + Clone;
    type Curve: crate::dvt_math::Curve + Clone;
}

// pub trait DvtSetup: DvtSetupBase
// where
//     <Self::GenCrypto as CryptoKeys>::Pubkey:
//         ByteConvertible<RawBytes = <<Self::Curve as crate::dvt_math::Curve>::Point as ByteConvertible>::RawBytes>,
// {
// }
// impl<T> DvtSetup for T
// where
//     T: DvtSetupBase,
//     <T::GenCrypto as CryptoKeys>::Pubkey:
//         ByteConvertible<RawBytes = <<Self::Curve as crate::dvt_math::Curve>::Point as ByteConvertible>::RawBytes>,
// {
// }


#[derive(Clone, Serialize, Deserialize)]
pub struct BlsDvtWithSecp256k1Commitment {}

impl DvtSetup for BlsDvtWithSecp256k1Commitment {
    type GenCrypto = BlsCrypto;
    type CommitmentCrypto = BlsCrypto;
    type Curve = crate::dvt_math::BlsG1Curve;
}

fn pesho() {

    let raw = BLSPubkeyRaw::from_hex("90346f9c5f3c09d96ea02acd0220daa8459f03866ed938c798e3716e42c7e033c9a7ef66a10f83af06d5c00b508c6d0f").unwrap();

    let p1 = <<<BlsDvtWithSecp256k1Commitment as DvtSetup>::Curve as dvt_math::Curve>::Point as ByteConvertible>::RawBytes::from_hex("90346f9c5f3c09d96ea02acd0220daa8459f03866ed938c798e3716e42c7e033c9a7ef66a10f83af06d5c00b508c6d0f").unwrap();
    let p2 = <<<BlsDvtWithSecp256k1Commitment as DvtSetup>::GenCrypto as CryptoKeys>::Pubkey as ByteConvertible>::RawBytes::from_hex("90346f9c5f3c09d96ea02acd0220daa8459f03866ed938c798e3716e42c7e033c9a7ef66a10f83af06d5c00b508c6d0f").unwrap();

}

#[derive(Clone, Serialize, Deserialize)]
pub struct GenerateSettings {
    #[serde(rename = "n")]
    pub n: u8,
    #[serde(rename = "k")]
    pub k: u8,
    #[serde(rename = "gen_id")]
    pub gen_id: DvtGenId,
}

pub type VerificationHashes = Vec<SHA256Raw>;

#[derive(Clone, Serialize, Deserialize)]
pub struct InitialCommitment<C>
where
    C: crate::dvt_math::Curve,
{
    #[serde(rename = "hash")]
    pub hash: SHA256Raw,
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "base_pubkeys")]
    pub base_pubkeys: Vec<<C::Point as ByteConvertible>::RawBytes>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExchangedSecret {
    #[serde(rename = "dst_base_hash")]
    pub dst_base_hash: SHA256Raw,
    #[serde(rename = "shared_secret")]
    pub secret: BLSSecretRaw,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Commitment<Crypto>
where
    Crypto: CryptoKeys,
{
    #[serde(rename = "hash")]
    pub hash: SHA256Raw,
    #[serde(rename = "pubkey")]
    pub pubkey: <Crypto::Pubkey as ByteConvertible>::RawBytes,
    #[serde(rename = "signature")]
    pub signature: <Crypto::Signature as ByteConvertible>::RawBytes,
}

type BlsCommitment = Commitment<BlsCrypto>;
//type Secp256k1Commitment = Commitment<Secp256k1Crypto>;

#[derive(Clone, Serialize, Deserialize)]
pub struct SeedExchangeCommitment {
    #[serde(rename = "initial_commitment_hash")]
    pub initial_commitment_hash: SHA256Raw,
    #[serde(rename = "ssecret")]
    pub shared_secret: ExchangedSecret,
    #[serde(rename = "commitment")]
    pub commitment: BlsCommitment,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SharedData<Setup>
where 
    Setup: DvtSetup,{
    #[serde(rename = "base_hashes")]
    pub verification_hashes: VerificationHashes,
    #[serde(rename = "initial_commitment")]
    pub initial_commitment: InitialCommitment<Setup::Curve>,
    #[serde(rename = "seeds_exchange_commitment")]
    pub seeds_exchange_commitment: SeedExchangeCommitment,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Generation<Setup>
where
    Setup: DvtSetup,
{
    #[serde(rename = "base_pubkeys")]
    pub verification_vector: Vec<<<Setup::Curve as crate::dvt_math::Curve>::Point as ByteConvertible>::RawBytes>,
    #[serde(rename = "base_hash")]
    pub base_hash: SHA256Raw,
    #[serde(rename = "partial_pubkey")]
    pub partial_pubkey: <<Setup::GenCrypto as CryptoKeys>::Pubkey as ByteConvertible>::RawBytes,
    #[serde(rename = "message_cleartext")]
    pub message_cleartext: String,
    #[serde(rename = "message_signature")]
    pub message_signature: <<Setup::GenCrypto as CryptoKeys>::Signature as ByteConvertible>::RawBytes,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FinalizationData<Setup>
where
    Setup: DvtSetup,
{
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "generations")]
    pub generations: Vec<Generation<Setup>>,
    #[serde(rename = "aggregate_pubkey")]
    pub aggregate_pubkey: <<Setup::GenCrypto as CryptoKeys>::Pubkey as ByteConvertible>::RawBytes,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BadPartialShareGeneration<Setup> where
    Setup: DvtSetup{
    #[serde(rename = "base_pubkeys")]
    pub verification_vector: Vec<<<Setup::Curve as crate::dvt_math::Curve>::Point as ByteConvertible>::RawBytes>,
    #[serde(rename = "base_hash")]
    pub base_hash: SHA256Raw,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BadPartialShare<Setup>
where
    Setup: DvtSetup,
{
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "data")]
    pub data: Generation<Setup>,
    #[serde(rename = "commitment")]
    pub commitment: Commitment<Setup::CommitmentCrypto>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BadPartialShareData<Setup>
where
    Setup: DvtSetup,
{
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "generations")]
    pub generations: Vec<BadPartialShareGeneration<Setup>>,
    #[serde(rename = "bad_partial")]
    pub bad_partial: BadPartialShare<Setup>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BadEncryptedShare<Setup>
where
    Setup: DvtSetup,
{
    #[serde(rename = "sender_pubkey")]
    pub sender_pubkey: <<Setup::GenCrypto as CryptoKeys>::Pubkey as ByteConvertible>::RawBytes,
    #[serde(rename = "receiver_signature")]
    pub signature: <<Setup::GenCrypto as CryptoKeys>::Signature as ByteConvertible>::RawBytes,
    #[serde(rename = "receiver_pubkey")]
    pub receiver_pubkey: <<Setup::GenCrypto as CryptoKeys>::Pubkey as ByteConvertible>::RawBytes,
    #[serde(rename = "receiver_base_secrets_commitment_hash")]
    pub receiver_commitment_hash: SHA256Raw,
    #[serde(rename = "encrypted_data")]
    pub encrypted_message: String,
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "base_hashes")]
    pub base_hashes: VerificationHashes,
    #[serde(rename = "base_pubkeys")]
    pub base_pubkeys:
        Vec<<<Setup::Curve as crate::dvt_math::Curve>::Point as ByteConvertible>::RawBytes>,
}

macro_rules! define_display {
    ($name:ty) => {
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let text = match serde_json::to_string_pretty(self) {
                    Ok(text) => text,
                    Err(err) => err.to_string(),
                };
                write!(f, "{}", text)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let text = match serde_json::to_string_pretty(self) {
                    Ok(text) => text,
                    Err(err) => err.to_string(),
                };
                write!(f, "{}", text)
            }
        }
    };
}

#[macro_export]
macro_rules! for_each_dvt_type {
    ($macro:ident) => {
        $macro!(GenerateSettings);
        $macro!(InitialCommitment<crate::dvt_math::BlsG1Curve>);
        $macro!(SeedExchangeCommitment);
        $macro!(SharedData<BlsDvtWithSecp256k1Commitment>);
        $macro!(Generation<BlsDvtWithSecp256k1Commitment>);
        $macro!(FinalizationData<BlsDvtWithSecp256k1Commitment>);
        $macro!(BadPartialShareGeneration<BlsDvtWithSecp256k1Commitment>);
        $macro!(BadPartialShare<BlsDvtWithSecp256k1Commitment>);
        $macro!(BadPartialShareData<BlsDvtWithSecp256k1Commitment>);
        $macro!(BadEncryptedShare<BlsDvtWithSecp256k1Commitment>);
    };
}

for_each_dvt_type!(define_display);

pub trait AsByteArr {
    fn as_arr(&self) -> &[u8];
}

macro_rules! define_raw_type {
    ($name:ident, $size_const:ident) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
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
                Some(self.cmp(other))
            }
        }

        impl std::cmp::Ord for $name {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.0.cmp(&other.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let hex_str = hex::encode(self.0);
                serializer.serialize_str(&hex_str)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let hex_str = hex::encode(self.0);
                write!(f, "{}", hex_str)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let hex_str = hex::encode(self.0);
                write!(f, "{}", hex_str)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let hex_str = String::deserialize(deserializer)?;
                let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
                let arr: [u8; $size_const] = bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("Invalid {$name} length"))?;
                Ok($name(arr))
            }
        }

        impl traits::HexConvertible for $name {
            fn from_hex(hex: &str) -> Result<Self, hex::FromHexError> {
                let bytes: [u8; $size_const] = hex::decode(hex)?.try_into().unwrap();
                Ok(Self(bytes))
            }

            fn to_hex(&self) -> String {
                hex::encode(&self.0)
            }
        }
    };
}

pub const BLS_SIGNATURE_SIZE: usize = 96;
pub const BLS_PUBKEY_SIZE: usize = 48;
pub const BLS_UNCOMPRESSED_SIGNATURE_SIZE: usize = 192;
pub const BLS_UNCOMPRESSED_PUBKEY_SIZE: usize = 96;
pub const BLS_SECRET_SIZE: usize = 32;
pub const BLS_ID_SIZE: usize = 32;
pub const GEN_ID_SIZE: usize = 16;
pub const SHA256_SIZE: usize = 32;

pub const SECP256K1_PUBKEY_SIZE: usize = secp256k1::constants::PUBLIC_KEY_SIZE;
pub const SECP256K1_SIGNATURE_SIZE: usize = secp256k1::constants::COMPACT_SIGNATURE_SIZE;
pub const SECP256K1_SECRET_SIZE: usize = secp256k1::constants::SECRET_KEY_SIZE;

#[macro_export]
macro_rules! for_each_raw_type {
    ($macro:ident) => {
        $macro!(DvtGenId, GEN_ID_SIZE);
        $macro!(BLSPubkeyRaw, BLS_PUBKEY_SIZE);
        $macro!(BLSSignatureRaw, BLS_SIGNATURE_SIZE);
        $macro!(BLSUncompressedPubkeyRaw, BLS_UNCOMPRESSED_PUBKEY_SIZE);
        $macro!(BLSUncompressedSignatureRaw, BLS_UNCOMPRESSED_SIGNATURE_SIZE);
        $macro!(BLSSecretRaw, BLS_SECRET_SIZE);
        $macro!(BLSIdRaw, BLS_ID_SIZE);
        $macro!(SHA256Raw, SHA256_SIZE);
        $macro!(SECP256K1PubkeyRaw, SECP256K1_PUBKEY_SIZE);
        $macro!(SECP256K1SignatureRaw, SECP256K1_SIGNATURE_SIZE);
        $macro!(SECP256K1SecretRaw, SECP256K1_SECRET_SIZE);
    };
}

for_each_raw_type!(define_raw_type);
