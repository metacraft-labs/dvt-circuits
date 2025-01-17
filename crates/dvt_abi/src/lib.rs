use serde::de::DeserializeOwned;
use serde::Deserialize;

use validator::Validate;

use hex::decode;
use std::fs::File;
use std::io::Read;

use std::error::Error;

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
    verification_hashes: DvtVerificationHashes,
    initial_commitment: DvtInitialCommitment,
    seeds_exchange_commitment: DvtShareExchangeCommitment,
}

#[derive(Debug, Deserialize)]
pub struct DvtGeneration {
    #[serde(rename(deserialize = "base_pubkeys"))]
    verification_vector: Vec<String>,
    base_hash: String,
    partial_pubkey: String,
    message_cleartext: String,
    message_signature: String,
}


#[derive(Debug, Deserialize)]
pub struct DvtFinalizationData {
    settings: DvtGenerateSettings,
    generations: Vec<DvtGeneration>,
    aggregate_pubkey: String,
}


#[derive(Debug)]
pub struct AbiVerificationVector {
    pub pubkeys: Vec<BLSPubkey>,
}

#[derive(Debug)]
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

fn decode_hex<const N: usize>(input: &str) -> Result<[u8; N], Box<dyn Error>> {
    let bytes = decode(input).map_err(|e| format!("Failed to decode input: {}", e))?;

    // Check the length
    if bytes.len() != N {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Expected length {}, but got {}", N, bytes.len()),
        )));
    }

    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

impl DvtVerificationVector {
    pub fn to_abi(&self) -> Result<AbiVerificationVector, Box<dyn std::error::Error>> {
        Ok(AbiVerificationVector {
            pubkeys: self
                .pubkeys
                .iter()
                .map(|p| decode_hex::<BLS_PUBKEY_SIZE>(p))
                .collect::<Result<Vec<[u8; BLS_PUBKEY_SIZE]>, _>>()
                .map_err(|e| format!("Invalid pubkey: {}", e))?,
        })
    }
}

impl DvtGenerateSettings {
    pub fn to_abi(&self) -> Result<AbiGenerateSettings, Box<dyn std::error::Error>> {
        Ok(AbiGenerateSettings {
            n: self.n,
            k: self.k,
            gen_id: decode_hex::<GEN_ID_SIZE>(&self.gen_id)
                .map_err(|e| format!("Invalid gen_id: {}", e))?,
        })
    }
}

impl DvtInitialCommitment {
    pub fn to_abi(&self) -> Result<AbiInitialCommitment, Box<dyn std::error::Error>> {
        Ok(AbiInitialCommitment {
            hash: decode_hex::<SHA256_SIZE>(&self.hash)
                .map_err(|e| format!("Invalid hash: {}", e))?,
            settings: self
                .settings
                .to_abi()
                .map_err(|e| format!("Invalid settings: {}", e))?,
            verification_vector: self
                .verification_vector
                .to_abi()
                .map_err(|e| format!("Invalid verification vector: {}", e))?,
        })
    }
}

impl DvtExchangedSecret {
    pub fn to_abi(&self) -> Result<AbiExchangedSecret, Box<dyn std::error::Error>> {
        Ok(AbiExchangedSecret {
            src_id: decode_hex::<BLS_ID_SIZE>(&self.src_id)
                .map_err(|e| format!("Invalid id: {}", e))?,
            dst_id: decode_hex::<BLS_ID_SIZE>(&self.dst_id)
                .map_err(|e| format!("Invalid id: {}", e))?,
            secret: decode_hex::<BLS_SECRET_SIZE>(&self.secret)
                .map_err(|e| format!("Invalid secret: {}", e))?,
            dst_base_hash: decode_hex::<SHA256_SIZE>(&self.dst_base_hash)
                .map_err(|e| format!("Invalid dst_base_hash: {}", e))?,
        })
    }
}

impl DvtCommitment {
    pub fn to_abi(&self) -> Result<AbiCommitment, Box<dyn std::error::Error>> {
        Ok(AbiCommitment {
            hash: decode_hex::<SHA256_SIZE>(&self.hash)
                .map_err(|e| format!("Invalid hash: {}", e))?,
            pubkey: decode_hex::<BLS_PUBKEY_SIZE>(&self.pubkey)
                .map_err(|e| format!("Invalid pubkey: {}", e))?,
            signature: decode_hex::<BLS_SIGNATURE_SIZE>(&self.signature)
                .map_err(|e| format!("Invalid signature: {}", e))?,
        })
    }
}

impl DvtShareExchangeCommitment {
    pub fn to_abi(&self) -> Result<AbiSeedExchangeCommitment, Box<dyn std::error::Error>> {
        Ok(AbiSeedExchangeCommitment {
            initial_commitment_hash: decode_hex::<SHA256_SIZE>(&self.initial_commitment_hash)
                .map_err(|e| format!("Invalid initial_commitment_hash: {}", e))?,
            shared_secret: self
                .shared_secret
                .to_abi()
                .map_err(|e| format!("Invalid shared_secret: {}", e))?,
            commitment: self
                .commitment
                .to_abi()
                .map_err(|e| format!("Invalid commitment: {}", e))?,
        })
    }
}

impl DvtBlsSharedData {
    pub fn to_abi(&self) -> Result<AbiBlsSharedData, Box<dyn std::error::Error>> {
        Ok(AbiBlsSharedData {
            verification_hashes: self
                .verification_hashes
                .iter()
                .map(|h| decode_hex::<SHA256_SIZE>(h))
                .collect::<Result<Vec<[u8; SHA256_SIZE]>, _>>()
                .map_err(|e| format!("Invalid hash: {}", e))?,
            initial_commitment: self
                .initial_commitment
                .to_abi()
                .map_err(|e| format!("Invalid initial_commitment: {}", e))?,
            seeds_exchange_commitment: self
                .seeds_exchange_commitment
                .to_abi()
                .map_err(|e| format!("Invalid seeds_exchange_commitment: {}", e))?,
        })
    }
}

impl DvtGeneration {
    pub fn to_abi(&self) -> Result<AbiGeneration, Box<dyn std::error::Error>> {
        Ok(AbiGeneration {
            verification_vector: self.verification_vector.iter().map(|p| decode_hex::<BLS_PUBKEY_SIZE>(p))
            .collect::<Result<Vec<[u8; BLS_PUBKEY_SIZE]>, _>>()
            .map_err(|e| format!("Invalid pubkey: {}", e))?,
            base_hash: decode_hex::<SHA256_SIZE>(&self.base_hash)
                .map_err(|e| format!("Invalid base_hash: {}", e))?,
            partial_pubkey: decode_hex::<BLS_PUBKEY_SIZE>(&self.partial_pubkey).map_err(|e| format!("Invalid partial_pubkey: {}", e))?,
            message_cleartext: self.message_cleartext.as_bytes().to_vec(),
            message_signature: decode_hex::<BLS_SIGNATURE_SIZE>(&self.message_signature).map_err(|e| format!("Invalid message_signature: {}", e))?,
        })
    }
}   

impl DvtFinalizationData {  
    pub fn to_abi(&self) -> Result<AbiFinalizationData, Box<dyn std::error::Error>> {
        Ok(AbiFinalizationData {
            settings: self.settings.to_abi().map_err(|e| format!("Invalid settings: {}", e))?,
            generations: self.generations.iter().map(|g| g.to_abi()).collect::<Result<Vec<AbiGeneration>, _>>()?,
            aggregate_pubkey: decode_hex::<BLS_PUBKEY_SIZE>(&self.aggregate_pubkey)
                .map_err(|e| format!("Invalid aggregate_pubkey: {}", e))?,
        })
    }
}

pub fn read_data_from_json_file<T>(filename: &str) -> Result<T, Box<dyn Error>> where T: DeserializeOwned {
    let mut file = File::open(filename).map_err(|e| format!("Error opening file: {}", e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Error reading file: {}", e))?;

    let data: T = serde_json::from_str(&contents)?;
    Ok(data)

}
