use crate::crypto::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateSettings {
    #[serde(rename = "n")]
    pub n: u8,
    #[serde(rename = "k")]
    pub k: u8,
    #[serde(rename = "gen_id")]
    pub gen_id: DvtGenId,
}

pub type VerificationHashes = Vec<SHA256Raw>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialCommitment {
    #[serde(rename = "hash")]
    pub hash: SHA256Raw,
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "base_pubkeys")]
    pub base_pubkeys: Vec<BLSPubkeyRaw>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExchangedSecret {
    #[serde(rename = "dst_base_hash")]
    pub dst_base_hash: SHA256Raw,
    #[serde(rename = "shared_secret")]
    pub secret: BLSSecretRaw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commitment {
    #[serde(rename = "hash")]
    pub hash: SHA256Raw,
    #[serde(rename = "pubkey")]
    pub pubkey: BLSPubkeyRaw,
    #[serde(rename = "signature")]
    pub signature: BLSSignatureRaw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedExchangeCommitment {
    #[serde(rename = "initial_commitment_hash")]
    pub initial_commitment_hash: SHA256Raw,
    #[serde(rename = "ssecret")]
    pub shared_secret: ExchangedSecret,
    #[serde(rename = "commitment")]
    pub commitment: Commitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlsSharedData {
    #[serde(rename = "base_hashes")]
    pub verification_hashes: VerificationHashes,
    #[serde(rename = "initial_commitment")]
    pub initial_commitment: InitialCommitment,
    #[serde(rename = "seeds_exchange_commitment")]
    pub seeds_exchange_commitment: SeedExchangeCommitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Generation {
    #[serde(rename = "base_pubkeys")]
    pub verification_vector: Vec<BLSPubkeyRaw>,
    #[serde(rename = "base_hash")]
    pub base_hash: SHA256Raw,
    #[serde(rename = "partial_pubkey")]
    pub partial_pubkey: BLSPubkeyRaw,
    #[serde(rename = "message_cleartext")]
    pub message_cleartext: String,
    #[serde(rename = "message_signature")]
    pub message_signature: BLSSignatureRaw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizationData {
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "generations")]
    pub generations: Vec<Generation>,
    #[serde(rename = "aggregate_pubkey")]
    pub aggregate_pubkey: BLSPubkeyRaw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadPartialShareGeneration {
    #[serde(rename = "base_pubkeys")]
    pub verification_vector: Vec<BLSPubkeyRaw>,
    #[serde(rename = "base_hash")]
    pub base_hash: SHA256Raw,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadPartialShare {
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "data")]
    pub data: Generation,
    #[serde(rename = "commitment")]
    pub commitment: Commitment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadPartialShareData {
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "generations")]
    pub generations: Vec<BadPartialShareGeneration>,
    #[serde(rename = "bad_partial")]
    pub bad_partial: BadPartialShare,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadEncryptedShare {
    #[serde(rename = "sender_pubkey")]
    pub sender_pubkey: BLSPubkeyRaw,
    #[serde(rename = "receiver_signature")]
    pub signature: BLSSignatureRaw,
    #[serde(rename = "receiver_pubkey")]
    pub receiver_pubkey: BLSPubkeyRaw,
    #[serde(rename = "receiver_base_secrets_commitment_hash")]
    pub receiver_commitment_hash: SHA256Raw,
    #[serde(rename = "encrypted_data")]
    pub encrypted_message: String,
    #[serde(rename = "settings")]
    pub settings: GenerateSettings,
    #[serde(rename = "base_hashes")]
    pub base_hashes: VerificationHashes,
    #[serde(rename = "base_pubkeys")]
    pub base_pubkeys: Vec<BLSPubkeyRaw>,
}
