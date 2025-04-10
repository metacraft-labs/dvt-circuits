use crypto::*;
use hex::decode;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::hash::Hash;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;
use validator::Validate;

/// ---------------------------------------------------------------------------
/// DVT Data Structures (input side)
/// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct DvtGenerateSettings {
    pub n: u8,
    pub k: u8,
    pub gen_id: String,
}

pub type DvtVerificationHashes = Vec<String>;

#[derive(Debug, Deserialize, Validate)]
pub struct DvtInitialCommitment {
    pub hash: String,
    pub settings: DvtGenerateSettings,
    #[serde(rename(deserialize = "base_pubkeys"))]
    pub base_pubkeys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DvtCommitment {
    pub hash: String,
    pub pubkey: String,
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct DvtShareExchangeCommitment {
    pub initial_commitment_hash: String,
    #[serde(rename(deserialize = "ssecret"))]
    pub shared_secret: DvtExchangedSecret,
    pub commitment: DvtCommitment,
}

#[derive(Debug, Deserialize)]
pub struct DvtExchangedSecret {
    #[serde(rename(deserialize = "shared_secret"))]
    pub secret: String,
    #[serde(rename(deserialize = "dst_base_hash"))]
    pub dst_base_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct DvtShare {
    pub id: String,
    pub pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct DvtBlsSharedData {
    #[serde(rename(deserialize = "base_hashes"))]
    pub verification_hashes: DvtVerificationHashes,
    pub initial_commitment: DvtInitialCommitment,
    pub seeds_exchange_commitment: DvtShareExchangeCommitment,
}

#[derive(Debug, Deserialize)]
pub struct DvtGeneration {
    #[serde(rename(deserialize = "base_pubkeys"))]
    pub verification_vector: Vec<String>,
    pub base_hash: String,
    pub partial_pubkey: String,
    pub message_cleartext: String,
    pub message_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct DvtFinalizationData {
    pub settings: DvtGenerateSettings,
    pub generations: Vec<DvtGeneration>,
    pub aggregate_pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct DvtBadPartialShareGeneration {
    #[serde(rename(deserialize = "base_pubkeys"))]
    pub verification_vector: Vec<String>,
    pub base_hash: String,
}

#[derive(Debug, Deserialize)]
pub struct DvtBadPartialShare {
    pub settings: DvtGenerateSettings,
    pub data: DvtGeneration,
    pub commitment: DvtCommitment,
}

#[derive(Debug, Deserialize)]
pub struct DvtBadPartialShareData {
    pub settings: DvtGenerateSettings,
    pub generations: Vec<DvtBadPartialShareGeneration>,
    pub bad_partial: DvtBadPartialShare,
}

#[derive(Debug, Deserialize)]
pub struct DvtBadEncryptedShare {
    #[serde(rename(deserialize = "sender_pubkey"))]
    pub sender_pubkey: String,
    #[serde(rename(deserialize = "receiver_signature"))]
    pub signature: String,
    #[serde(rename(deserialize = "receiver_pubkey"))]
    pub receiver_pubkey: String,
    #[serde(rename(deserialize = "receiver_base_secrets_commitment_hash"))]
    pub receiver_commitment_hash: String,
    #[serde(rename(deserialize = "encrypted_data"))]
    pub encrypted_message: String,
    #[serde(rename(deserialize = "settings"))]
    pub settings: DvtGenerateSettings,
    #[serde(rename(deserialize = "base_hashes"))]
    pub base_hashes: DvtVerificationHashes,
    #[serde(rename(deserialize = "base_pubkeys"))]
    pub base_pubkeys: Vec<String>,
}

/// ---------------------------------------------------------------------------
/// ABI Data Structures (output side)
/// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AbiGenerateSettings {
    pub n: u8,
    pub k: u8,
    pub gen_id: [u8; GEN_ID_SIZE],
}

pub type AbiVerificationHashes = Vec<SHA256Raw>;

#[derive(Debug)]
pub struct AbiInitialCommitment {
    pub hash: SHA256Raw,
    pub settings: AbiGenerateSettings,
    pub base_pubkeys: Vec<BLSPubkeyRaw>,
}

#[derive(Debug)]
pub struct AbiExchangedSecret {
    pub dst_base_hash: SHA256Raw,
    pub secret: BLSSecretRaw,
}

pub trait Commitment {
    type HashRaw: HexConvertable + Sized + AsByteArr;
    type PubkeyRaw: HexConvertable + Sized + AsByteArr;
    type SignatureRaw: HexConvertable + Sized + AsByteArr;

    const HASH_SIZE: usize;
    const PUBKEY_SIZE: usize;
    const SIGNATURE_SIZE: usize;
}

#[derive(Debug)]
pub struct BlsCommitment {}

impl Commitment for BlsCommitment {
    type HashRaw = SHA256Raw;
    type PubkeyRaw = BLSPubkeyRaw;
    type SignatureRaw = BLSSignatureRaw;

    const HASH_SIZE: usize = SHA256_SIZE;
    const PUBKEY_SIZE: usize = BLS_PUBKEY_SIZE;
    const SIGNATURE_SIZE: usize = BLS_SIGNATURE_SIZE;
}

#[derive(Debug)]
pub struct AbiCommitment<CommitmentType>
where
    CommitmentType: Commitment,
{
    pub hash: CommitmentType::HashRaw,
    pub pubkey: CommitmentType::PubkeyRaw,
    pub signature: CommitmentType::SignatureRaw,
}

#[derive(Debug)]
pub struct AbiSeedExchangeCommitment {
    pub initial_commitment_hash: SHA256Raw,
    pub shared_secret: AbiExchangedSecret,
    pub commitment: AbiCommitment<BlsCommitment>,
}

#[derive(Debug)]
pub struct AbiBlsSharedData {
    pub verification_hashes: AbiVerificationHashes,
    pub initial_commitment: AbiInitialCommitment,
    pub seeds_exchange_commitment: AbiSeedExchangeCommitment,
}

#[derive(Debug, Clone)]
pub struct AbiGeneration {
    pub verification_vector: Vec<BLSPubkeyRaw>,
    pub base_hash: SHA256Raw,
    pub partial_pubkey: BLSPubkeyRaw,
    pub message_cleartext: Vec<u8>,
    pub message_signature: BLSSignatureRaw,
}

#[derive(Debug)]
pub struct AbiFinalizationData {
    pub settings: AbiGenerateSettings,
    pub generations: Vec<AbiGeneration>,
    pub aggregate_pubkey: BLSPubkeyRaw,
}

#[derive(Debug, Clone)]
pub struct AbiBadPartialShareGeneration {
    pub verification_vector: Vec<BLSPubkeyRaw>,
    pub base_hash: SHA256Raw,
}

#[derive(Debug)]
pub struct AbiBadPartialShare {
    pub settings: AbiGenerateSettings,
    pub data: AbiGeneration,
    pub commitment: AbiCommitment<BlsCommitment>,
}

#[derive(Debug)]
pub struct AbiBadPartialShareData {
    pub settings: AbiGenerateSettings,
    pub generations: Vec<AbiBadPartialShareGeneration>,
    pub bad_partial: AbiBadPartialShare,
}

#[derive(Debug)]
pub struct AbiBadEncryptedShare {
    pub sender_pubkey: BLSPubkeyRaw,
    pub signature: BLSSignatureRaw,
    pub receiver_pubkey: BLSPubkeyRaw,
    pub receiver_commitment_hash: SHA256Raw,
    pub encrypted_message: Vec<u8>,
    pub settings: AbiGenerateSettings,
    pub base_hashes: AbiVerificationHashes,
    pub base_pubkeys: Vec<BLSPubkeyRaw>,
}

/// ---------------------------------------------------------------------------
/// Trait: ToAbi
///
/// Allows a "DvtX" type to convert itself to an "AbiX" type.
/// We'll use associated type T to indicate which ABI type it produces.
/// ---------------------------------------------------------------------------
pub trait ToAbi<T> {
    fn to_abi(&self) -> Result<T, Box<dyn Error>>;
}

fn decode_hex<const N: usize>(input: &str) -> Result<[u8; N], Box<dyn Error>> {
    let bytes = decode(input).map_err(|e| format!("Failed to decode input: {e}"))?;
    if bytes.len() != N {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Expected length {N}, but got {}", bytes.len()),
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// ---------------------------------------------------------------------------
/// Implementations of ToAbi for each Dvt type -> corresponding Abi type
/// ---------------------------------------------------------------------------
impl ToAbi<AbiGenerateSettings> for DvtGenerateSettings {
    fn to_abi(&self) -> Result<AbiGenerateSettings, Box<dyn Error>> {
        Ok(AbiGenerateSettings {
            n: self.n,
            k: self.k,
            gen_id: decode_hex::<GEN_ID_SIZE>(&self.gen_id)
                .map_err(|e| format!("Invalid gen_id: {e}"))?,
        })
    }
}

impl ToAbi<AbiInitialCommitment> for DvtInitialCommitment {
    fn to_abi(&self) -> Result<AbiInitialCommitment, Box<dyn Error>> {
        Ok(AbiInitialCommitment {
            hash: SHA256Raw::from_hex(&self.hash).map_err(|e| format!("Invalid hash: {e}"))?,
            settings: self
                .settings
                .to_abi()
                .map_err(|e| format!("Invalid settings: {e}"))?,
            base_pubkeys: self
                .base_pubkeys
                .iter()
                .map(|p| BLSPubkeyRaw::from_hex(p))
                .collect::<Result<Vec<BLSPubkeyRaw>, _>>()
                .map_err(|e| format!("Invalid pubkey: {e}"))?,
        })
    }
}

impl ToAbi<AbiExchangedSecret> for DvtExchangedSecret {
    fn to_abi(&self) -> Result<AbiExchangedSecret, Box<dyn Error>> {
        Ok(AbiExchangedSecret {
            secret: BLSSecretRaw::from_hex(&self.secret)
                .map_err(|e| format!("Invalid secret: {e}"))?,
            dst_base_hash: SHA256Raw::from_hex(&self.dst_base_hash)
                .map_err(|e| format!("Invalid dst_base_hash: {e}"))?,
        })
    }
}

impl<T: Commitment> ToAbi<AbiCommitment<T>> for DvtCommitment {
    fn to_abi(&self) -> Result<AbiCommitment<T>, Box<dyn Error>> {
        Ok(AbiCommitment::<T> {
            hash: T::HashRaw::from_hex(&self.hash).map_err(|e| format!("Invalid hash: {e}"))?,
            pubkey: T::PubkeyRaw::from_hex(&self.pubkey)
                .map_err(|e| format!("Invalid pubkey: {e}"))?,
            signature: T::SignatureRaw::from_hex(&self.signature)
                .map_err(|e| format!("Invalid signature: {e}"))?,
        })
    }
}

impl ToAbi<AbiSeedExchangeCommitment> for DvtShareExchangeCommitment {
    fn to_abi(&self) -> Result<AbiSeedExchangeCommitment, Box<dyn Error>> {
        Ok(AbiSeedExchangeCommitment {
            initial_commitment_hash: SHA256Raw::from_hex(&self.initial_commitment_hash)
                .map_err(|e| format!("Invalid initial_commitment_hash: {e}"))?,
            shared_secret: self
                .shared_secret
                .to_abi()
                .map_err(|e| format!("Invalid shared_secret: {e}"))?,
            commitment: self
                .commitment
                .to_abi()
                .map_err(|e| format!("Invalid commitment: {e}"))?,
        })
    }
}

impl ToAbi<AbiBlsSharedData> for DvtBlsSharedData {
    fn to_abi(&self) -> Result<AbiBlsSharedData, Box<dyn Error>> {
        let verification_hashes = self
            .verification_hashes
            .iter()
            .map(|h| SHA256Raw::from_hex(h))
            .collect::<Result<Vec<SHA256Raw>, _>>()
            .map_err(|e| format!("Invalid verification hash: {e}"))?;

        Ok(AbiBlsSharedData {
            verification_hashes,
            initial_commitment: self
                .initial_commitment
                .to_abi()
                .map_err(|e| format!("Invalid initial_commitment: {e}"))?,
            seeds_exchange_commitment: self
                .seeds_exchange_commitment
                .to_abi()
                .map_err(|e| format!("Invalid seeds_exchange_commitment: {e}"))?,
        })
    }
}

impl ToAbi<AbiGeneration> for DvtGeneration {
    fn to_abi(&self) -> Result<AbiGeneration, Box<dyn Error>> {
        let verification_vector = self
            .verification_vector
            .iter()
            .map(|p| BLSPubkeyRaw::from_hex(p))
            .collect::<Result<Vec<BLSPubkeyRaw>, _>>()
            .map_err(|e| format!("Invalid pubkey: {e}"))?;

        Ok(AbiGeneration {
            verification_vector,
            base_hash: SHA256Raw::from_hex(&self.base_hash)
                .map_err(|e| format!("Invalid base_hash: {e}"))?,
            partial_pubkey: BLSPubkeyRaw::from_hex(&self.partial_pubkey)
                .map_err(|e| format!("Invalid partial_pubkey: {e}"))?,
            message_cleartext: self.message_cleartext.as_bytes().to_vec(),
            message_signature: BLSSignatureRaw::from_hex(&self.message_signature)
                .map_err(|e| format!("Invalid message_signature: {e}"))?,
        })
    }
}

impl ToAbi<AbiFinalizationData> for DvtFinalizationData {
    fn to_abi(&self) -> Result<AbiFinalizationData, Box<dyn Error>> {
        let settings = self
            .settings
            .to_abi()
            .map_err(|e| format!("Invalid settings: {e}"))?;

        let generations = self
            .generations
            .iter()
            .map(|g| g.to_abi())
            .collect::<Result<Vec<AbiGeneration>, _>>()?;

        let aggregate_pubkey = BLSPubkeyRaw::from_hex(&self.aggregate_pubkey)
            .map_err(|e| format!("Invalid aggregate_pubkey: {e}"))?;

        Ok(AbiFinalizationData {
            settings,
            generations,
            aggregate_pubkey,
        })
    }
}

impl ToAbi<AbiBadPartialShareGeneration> for DvtBadPartialShareGeneration {
    fn to_abi(&self) -> Result<AbiBadPartialShareGeneration, Box<dyn Error>> {
        let verification_vector = self
            .verification_vector
            .iter()
            .map(|p| BLSPubkeyRaw::from_hex(p))
            .collect::<Result<Vec<BLSPubkeyRaw>, _>>()
            .map_err(|e| format!("Invalid pubkey: {e}"))?;

        let base_hash =
            SHA256Raw::from_hex(&self.base_hash).map_err(|e| format!("Invalid base_hash: {e}"))?;

        Ok(AbiBadPartialShareGeneration {
            verification_vector,
            base_hash,
        })
    }
}

impl ToAbi<AbiBadPartialShare> for DvtBadPartialShare {
    fn to_abi(&self) -> Result<AbiBadPartialShare, Box<dyn Error>> {
        Ok(AbiBadPartialShare {
            settings: self
                .settings
                .to_abi()
                .map_err(|e| format!("Invalid settings: {e}"))?,
            data: self
                .data
                .to_abi()
                .map_err(|e| format!("Invalid partial_data: {e}"))?,
            commitment: self
                .commitment
                .to_abi()
                .map_err(|e| format!("Invalid commitment: {e}"))?,
        })
    }
}

impl ToAbi<AbiBadPartialShareData> for DvtBadPartialShareData {
    fn to_abi(&self) -> Result<AbiBadPartialShareData, Box<dyn Error>> {
        let settings = self
            .settings
            .to_abi()
            .map_err(|e| format!("Invalid settings: {e}"))?;

        let generations = self
            .generations
            .iter()
            .map(|g| g.to_abi())
            .collect::<Result<Vec<AbiBadPartialShareGeneration>, _>>()?;

        let bad_partial = self
            .bad_partial
            .to_abi()
            .map_err(|e| format!("Invalid bad_partial: {e}"))?;

        Ok(AbiBadPartialShareData {
            settings,
            generations,
            bad_partial,
        })
    }
}

impl ToAbi<AbiBadEncryptedShare> for DvtBadEncryptedShare {
    fn to_abi(&self) -> Result<AbiBadEncryptedShare, Box<dyn Error>> {
        Ok(AbiBadEncryptedShare {
            sender_pubkey: BLSPubkeyRaw::from_hex(&self.sender_pubkey)
                .map_err(|e| format!("Invalid sender_pubkey: {e}"))?,
            receiver_pubkey: BLSPubkeyRaw::from_hex(&self.receiver_pubkey)
                .map_err(|e| format!("Invalid receiver_pubkey: {e}"))?,
            signature: BLSSignatureRaw::from_hex(&self.signature)
                .map_err(|e| format!("Invalid signature: {e}"))?,
            receiver_commitment_hash: SHA256Raw::from_hex(&self.receiver_commitment_hash)
                .map_err(|e| format!("Invalid receiver_commitment_hash: {e}"))?,
            encrypted_message: decode(&self.encrypted_message)
                .map_err(|e| format!("Invalid encrypted_share: {e}"))?,
            settings: self
                .settings
                .to_abi()
                .map_err(|e| format!("Invalid settings: {e}"))?,
            base_hashes: self
                .base_hashes
                .iter()
                .map(|h| SHA256Raw::from_hex(h))
                .collect::<Result<Vec<SHA256Raw>, _>>()
                .map_err(|e| format!("Invalid base_hash: {e}"))?,
            base_pubkeys: self
                .base_pubkeys
                .iter()
                .map(|p| BLSPubkeyRaw::from_hex(p))
                .collect::<Result<Vec<BLSPubkeyRaw>, _>>()
                .map_err(|e| format!("Invalid base_pubkey: {e}"))?,
        })
    }
}

/// ---------------------------------------------------------------------------
/// File & JSON Helpers
/// ---------------------------------------------------------------------------
fn check_if_file_exists(path: &str) -> Result<(), Box<dyn Error>> {
    if !Path::new(path).exists() {
        return Err(format!("File '{}' does not exist.", path).into());
    }
    Ok(())
}

pub fn read_text_file(filename: &str) -> Result<String, Box<dyn Error>> {
    check_if_file_exists(filename)?;
    let mut file =
        File::open(filename).map_err(|e| format!("Error opening file {filename}: {e}"))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Error reading file {filename}: {e}"))?;
    Ok(contents)
}

pub fn read_data_from_json_file<T>(filename: &str) -> Result<T, Box<dyn Error>>
where
    T: DeserializeOwned,
{
    let contents = read_text_file(filename)?;
    let data: T = serde_json::from_str(&contents)
        .map_err(|e| format!("Error parsing JSON in {filename}: {e}"))?;
    Ok(data)
}
