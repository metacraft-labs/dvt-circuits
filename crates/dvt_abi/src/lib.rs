use hex::decode;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use validator::Validate;

/// ---------------------------------------------------------------------------
/// Constants & Type Aliases
/// ---------------------------------------------------------------------------
pub const BLS_SIGNATURE_SIZE: usize = 96;
pub const BLS_PUBKEY_SIZE: usize = 48;
pub const BLS_SECRET_SIZE: usize = 32;
pub const BLS_ID_SIZE: usize = 32;
pub const GEN_ID_SIZE: usize = 16;
pub const SHA256_SIZE: usize = 32;

pub type BLSPubkey = [u8; BLS_PUBKEY_SIZE];
pub type BLSSecret = [u8; BLS_SECRET_SIZE];
pub type BLSId = [u8; BLS_ID_SIZE];
pub type BLSSignature = [u8; BLS_SIGNATURE_SIZE];
pub type SHA256 = [u8; SHA256_SIZE];

/// ---------------------------------------------------------------------------
/// DVT Data Structures (input side)
/// ---------------------------------------------------------------------------
#[derive(Debug, Deserialize)]
pub struct DvtVerificationVector {
    #[serde(rename(deserialize = "base_pubkeys"))]
    pub pubkeys: Vec<String>,
}

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
    #[serde(rename(deserialize = "vvector"))]
    pub verification_vector: DvtVerificationVector,
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
    #[serde(rename(deserialize = "dst_share_id"))]
    pub dst_id: String,
    #[serde(rename(deserialize = "src_share_id"))]
    pub src_id: String,
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
    #[serde(rename(deserialize = "reseiver_base_secrets_commitment_hash"))]
    pub receiver_commitment_hash: String,
    #[serde(rename(deserialize = "encrypted_data"))]
    pub encrypted_message: String,
}

/// ---------------------------------------------------------------------------
/// ABI Data Structures (output side)
/// ---------------------------------------------------------------------------
#[derive(Debug)]
pub struct AbiVerificationVector {
    pub pubkeys: Vec<BLSPubkey>,
}

#[derive(Debug, Clone)]
pub struct AbiGenerateSettings {
    pub n: u8,
    pub k: u8,
    pub gen_id: [u8; GEN_ID_SIZE],
}

pub type AbiVerificationHashes = Vec<SHA256>;

#[derive(Debug)]
pub struct AbiInitialCommitment {
    pub hash: SHA256,
    pub settings: AbiGenerateSettings,
    pub verification_vector: AbiVerificationVector,
}

#[derive(Debug)]
pub struct AbiExchangedSecret {
    pub src_id: BLSId,
    pub dst_id: BLSId,
    pub dst_base_hash: SHA256,
    pub secret: BLSSecret,
}

#[derive(Debug)]
pub struct AbiCommitment {
    pub hash: SHA256,
    pub pubkey: BLSPubkey,
    pub signature: BLSSignature,
}

#[derive(Debug)]
pub struct AbiSeedExchangeCommitment {
    pub initial_commitment_hash: SHA256,
    pub shared_secret: AbiExchangedSecret,
    pub commitment: AbiCommitment,
}

#[derive(Debug)]
pub struct AbiBlsSharedData {
    pub verification_hashes: AbiVerificationHashes,
    pub initial_commitment: AbiInitialCommitment,
    pub seeds_exchange_commitment: AbiSeedExchangeCommitment,
}

#[derive(Debug, Clone)]
pub struct AbiGeneration {
    pub verification_vector: Vec<BLSPubkey>,
    pub base_hash: SHA256,
    pub partial_pubkey: BLSPubkey,
    pub message_cleartext: Vec<u8>,
    pub message_signature: BLSSignature,
}

#[derive(Debug)]
pub struct AbiFinalizationData {
    pub settings: AbiGenerateSettings,
    pub generations: Vec<AbiGeneration>,
    pub aggregate_pubkey: BLSPubkey,
}

#[derive(Debug, Clone)]
pub struct AbiBadPartialShareGeneration {
    pub verification_vector: Vec<BLSPubkey>,
    pub base_hash: SHA256,
}

#[derive(Debug)]
pub struct AbiBadPartialShare {
    pub settings: AbiGenerateSettings,
    pub data: AbiGeneration,
    pub commitment: AbiCommitment,
}

#[derive(Debug)]
pub struct AbiBadPartialShareData {
    pub settings: AbiGenerateSettings,
    pub generations: Vec<AbiBadPartialShareGeneration>,
    pub bad_partial: AbiBadPartialShare,
}

#[derive(Debug)]
pub struct AbiBadEncryptedShare {
    pub sender_pubkey: BLSPubkey,
    pub signature: BLSSignature,
    pub receiver_pubkey: BLSPubkey,
    pub receiver_commitment_hash: SHA256,
    pub encrypted_message: Vec<u8>,
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
impl ToAbi<AbiVerificationVector> for DvtVerificationVector {
    fn to_abi(&self) -> Result<AbiVerificationVector, Box<dyn Error>> {
        let pubkeys = self
            .pubkeys
            .iter()
            .map(|p| decode_hex::<BLS_PUBKEY_SIZE>(p))
            .collect::<Result<Vec<[u8; BLS_PUBKEY_SIZE]>, _>>()
            .map_err(|e| format!("Invalid pubkey: {e}"))?;

        Ok(AbiVerificationVector { pubkeys })
    }
}

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
            hash: decode_hex::<SHA256_SIZE>(&self.hash)
                .map_err(|e| format!("Invalid hash: {e}"))?,
            settings: self
                .settings
                .to_abi()
                .map_err(|e| format!("Invalid settings: {e}"))?,
            verification_vector: self
                .verification_vector
                .to_abi()
                .map_err(|e| format!("Invalid verification vector: {e}"))?,
        })
    }
}

impl ToAbi<AbiExchangedSecret> for DvtExchangedSecret {
    fn to_abi(&self) -> Result<AbiExchangedSecret, Box<dyn Error>> {
        Ok(AbiExchangedSecret {
            src_id: decode_hex::<BLS_ID_SIZE>(&self.src_id)
                .map_err(|e| format!("Invalid src_id: {e}"))?,
            dst_id: decode_hex::<BLS_ID_SIZE>(&self.dst_id)
                .map_err(|e| format!("Invalid dst_id: {e}"))?,
            secret: decode_hex::<BLS_SECRET_SIZE>(&self.secret)
                .map_err(|e| format!("Invalid secret: {e}"))?,
            dst_base_hash: decode_hex::<SHA256_SIZE>(&self.dst_base_hash)
                .map_err(|e| format!("Invalid dst_base_hash: {e}"))?,
        })
    }
}

impl ToAbi<AbiCommitment> for DvtCommitment {
    fn to_abi(&self) -> Result<AbiCommitment, Box<dyn Error>> {
        Ok(AbiCommitment {
            hash: decode_hex::<SHA256_SIZE>(&self.hash)
                .map_err(|e| format!("Invalid hash: {e}"))?,
            pubkey: decode_hex::<BLS_PUBKEY_SIZE>(&self.pubkey)
                .map_err(|e| format!("Invalid pubkey: {e}"))?,
            signature: decode_hex::<BLS_SIGNATURE_SIZE>(&self.signature)
                .map_err(|e| format!("Invalid signature: {e}"))?,
        })
    }
}

impl ToAbi<AbiSeedExchangeCommitment> for DvtShareExchangeCommitment {
    fn to_abi(&self) -> Result<AbiSeedExchangeCommitment, Box<dyn Error>> {
        Ok(AbiSeedExchangeCommitment {
            initial_commitment_hash: decode_hex::<SHA256_SIZE>(&self.initial_commitment_hash)
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
            .map(|h| decode_hex::<SHA256_SIZE>(h))
            .collect::<Result<Vec<[u8; SHA256_SIZE]>, _>>()
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
            .map(|p| decode_hex::<BLS_PUBKEY_SIZE>(p))
            .collect::<Result<Vec<[u8; BLS_PUBKEY_SIZE]>, _>>()
            .map_err(|e| format!("Invalid pubkey: {e}"))?;

        Ok(AbiGeneration {
            verification_vector,
            base_hash: decode_hex::<SHA256_SIZE>(&self.base_hash)
                .map_err(|e| format!("Invalid base_hash: {e}"))?,
            partial_pubkey: decode_hex::<BLS_PUBKEY_SIZE>(&self.partial_pubkey)
                .map_err(|e| format!("Invalid partial_pubkey: {e}"))?,
            message_cleartext: self.message_cleartext.as_bytes().to_vec(),
            message_signature: decode_hex::<BLS_SIGNATURE_SIZE>(&self.message_signature)
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

        let aggregate_pubkey = decode_hex::<BLS_PUBKEY_SIZE>(&self.aggregate_pubkey)
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
            .map(|p| decode_hex::<BLS_PUBKEY_SIZE>(p))
            .collect::<Result<Vec<[u8; BLS_PUBKEY_SIZE]>, _>>()
            .map_err(|e| format!("Invalid pubkey: {e}"))?;

        let base_hash = decode_hex::<SHA256_SIZE>(&self.base_hash)
            .map_err(|e| format!("Invalid base_hash: {e}"))?;

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
            sender_pubkey: decode_hex::<BLS_PUBKEY_SIZE>(&self.sender_pubkey)
                .map_err(|e| format!("Invalid sender_pubkey: {e}"))?,
            receiver_pubkey: decode_hex::<BLS_PUBKEY_SIZE>(&self.receiver_pubkey)
                .map_err(|e| format!("Invalid receiver_pubkey: {e}"))?,
            signature: decode_hex::<BLS_SIGNATURE_SIZE>(&self.signature)
                .map_err(|e| format!("Invalid signature: {e}"))?,
            receiver_commitment_hash: decode_hex::<SHA256_SIZE>(&self.receiver_commitment_hash)
                .map_err(|e| format!("Invalid receiver_commitment_hash: {e}"))?,
            encrypted_message: decode(&self.encrypted_message)
                .map_err(|e| format!("Invalid encrypted_share: {e}"))?,
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
