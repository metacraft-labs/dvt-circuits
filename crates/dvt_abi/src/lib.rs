use crypto::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize,};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiGenerateSettings {
    #[serde(rename(deserialize = "n"))]
    pub n: u8,
    #[serde(rename(deserialize = "k"))]
    pub k: u8,
    #[serde(rename(deserialize = "gen_id"))]
    pub gen_id: DvtGenId,
}

pub type AbiVerificationHashes = Vec<SHA256Raw>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiInitialCommitment {
    #[serde(rename(deserialize = "hash"))]
    pub hash: SHA256Raw,
    #[serde(rename(deserialize = "settings"))]
    pub settings: AbiGenerateSettings,
    #[serde(rename(deserialize = "base_pubkeys"))]
    pub base_pubkeys: Vec<BLSPubkeyRaw>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiExchangedSecret {
    #[serde(rename(deserialize = "dst_base_hash"))]
    pub dst_base_hash: SHA256Raw,
    #[serde(rename(deserialize = "shared_secret"))]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsCommitment {}

impl Commitment for BlsCommitment {
    type HashRaw = SHA256Raw;
    type PubkeyRaw = BLSPubkeyRaw;
    type SignatureRaw = BLSSignatureRaw;

    const HASH_SIZE: usize = SHA256_SIZE;
    const PUBKEY_SIZE: usize = BLS_PUBKEY_SIZE;
    const SIGNATURE_SIZE: usize = BLS_SIGNATURE_SIZE;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiCommitment<CommitmentType>
where
    CommitmentType: Commitment,
{
    #[serde(rename(deserialize = "hash"))]
    pub hash: CommitmentType::HashRaw,
    #[serde(rename(deserialize = "pubkey"))]
    pub pubkey: CommitmentType::PubkeyRaw,
    #[serde(rename(deserialize = "signature"))]
    pub signature: CommitmentType::SignatureRaw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiSeedExchangeCommitment {
    #[serde(rename(deserialize = "initial_commitment_hash"))]
    pub initial_commitment_hash: SHA256Raw,
    #[serde(rename(deserialize = "ssecret"))]
    pub shared_secret: AbiExchangedSecret,
    #[serde(rename(deserialize = "commitment"))]
    pub commitment: AbiCommitment<BlsCommitment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiBlsSharedData {
    #[serde(rename(deserialize = "base_hashes"))]
    pub verification_hashes: AbiVerificationHashes,
    #[serde(rename(deserialize = "initial_commitment"))]
    pub initial_commitment: AbiInitialCommitment,
    #[serde(rename(deserialize = "seeds_exchange_commitment"))]
    pub seeds_exchange_commitment: AbiSeedExchangeCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiGeneration {
    #[serde(rename(deserialize = "base_pubkeys"))]
    pub verification_vector: Vec<BLSPubkeyRaw>,
    #[serde(rename(deserialize = "base_hash"))]
    pub base_hash: SHA256Raw,
    #[serde(rename(deserialize = "partial_pubkey"))]
    pub partial_pubkey: BLSPubkeyRaw,
    #[serde(rename(deserialize = "message_cleartext"))]
    pub message_cleartext: String,
    #[serde(rename(deserialize = "message_signature"))]
    pub message_signature: BLSSignatureRaw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiFinalizationData {
    #[serde(rename(deserialize = "settings"))]
    pub settings: AbiGenerateSettings,
    #[serde(rename(deserialize = "generations"))]
    pub generations: Vec<AbiGeneration>,
    #[serde(rename(deserialize = "aggregate_pubkey"))]
    pub aggregate_pubkey: BLSPubkeyRaw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiBadPartialShareGeneration {
    #[serde(rename(deserialize = "base_pubkeys"))]
    pub verification_vector: Vec<BLSPubkeyRaw>,
    #[serde(rename(deserialize = "base_hash"))]
    pub base_hash: SHA256Raw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiBadPartialShare {
    #[serde(rename(deserialize = "settings"))]
    pub settings: AbiGenerateSettings,
    #[serde(rename(deserialize = "data"))]
    pub data: AbiGeneration,
    #[serde(rename(deserialize = "commitment"))]
    pub commitment: AbiCommitment<BlsCommitment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiBadPartialShareData {
    #[serde(rename(deserialize = "settings"))]
    pub settings: AbiGenerateSettings,
    #[serde(rename(deserialize = "generations"))]
    pub generations: Vec<AbiBadPartialShareGeneration>,
    #[serde(rename(deserialize = "bad_partial"))]
    pub bad_partial: AbiBadPartialShare,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiBadEncryptedShare {
    #[serde(rename(deserialize = "sender_pubkey"))]
    pub sender_pubkey: BLSPubkeyRaw,
    #[serde(rename(deserialize = "receiver_signature"))]
    pub signature: BLSSignatureRaw,
    #[serde(rename(deserialize = "receiver_pubkey"))]
    pub receiver_pubkey: BLSPubkeyRaw,
    #[serde(rename(deserialize = "receiver_base_secrets_commitment_hash"))]
    pub receiver_commitment_hash: SHA256Raw,
    #[serde(rename(deserialize = "encrypted_data"))]
    pub encrypted_message: String,
    #[serde(rename(deserialize = "settings"))]
    pub settings: AbiGenerateSettings,
    #[serde(rename(deserialize = "base_hashes"))]
    pub base_hashes: AbiVerificationHashes,
    #[serde(rename(deserialize = "base_pubkeys"))]
    pub base_pubkeys: Vec<BLSPubkeyRaw>,
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
