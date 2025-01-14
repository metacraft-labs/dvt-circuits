use serde::Deserialize;

use hex::decode;
use std::fs::File;
use std::io::Read;

use std::error::Error;


const BLS_SIGNATURE_SIZE: usize = 96;
const BLS_PUBKEY_SIZE: usize = 48;
const BLS_SECRET_SIZE: usize = 32;
const BLS_ID_SIZE: usize = 32;
const GEN_ID_SIZE: usize = 16;
const SHA256_SIZE: usize = 32;

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

#[derive(Debug, Deserialize)]
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
}

#[derive(Debug, Deserialize)]
pub struct DvtShare {
    pub id: String,
    pub pubkey: String,
}

#[derive(Debug, Deserialize)]
pub struct DvtData {
    pub settings: DvtGenerateSettings,
    pub verification_vectors: Vec<DvtVerificationVector>,
    pub shares: Vec<DvtShare>,
}

#[derive(Debug, Deserialize)]
pub struct DvtBlsSharedData {
    initial_commitment: DvtInitialCommitment,
    seeds_exchange_commitment: DvtShareExchangeCommitment,
}

#[derive(Debug)]
pub struct AbiVerificationVector {
    pub pubkeys: Vec<[u8; BLS_PUBKEY_SIZE]>,
}

#[derive(Debug)]
pub struct AbiGenerateSettings {
    pub n: u8,
    pub k: u8,
    pub gen_id: [u8; GEN_ID_SIZE],
}

#[derive(Debug)]
pub struct AbiInitialCommitment {
    pub hash: [u8; SHA256_SIZE],
    pub settings: AbiGenerateSettings,
    pub verification_vector: AbiVerificationVector,
}

#[derive(Debug)]
pub struct AbiExchangedSecret {
    pub src_id: [u8; BLS_ID_SIZE],
    pub dst_id: [u8; BLS_ID_SIZE],
    pub secret: [u8; BLS_SECRET_SIZE],
}

#[derive(Debug)]
pub struct AbiCommitment {
    pub hash: [u8; SHA256_SIZE],
    pub pubkey: [u8; BLS_PUBKEY_SIZE],
    pub signature: [u8; BLS_SIGNATURE_SIZE],
}

#[derive(Debug)]
pub struct AbiSeedExchangeCommitment {
    pub initial_commitment_hash: [u8; SHA256_SIZE],
    pub shared_secret: AbiExchangedSecret,
    pub commitment: AbiCommitment,
}

#[derive(Debug)]
pub struct AbiBlsSharedData {
    pub initial_commitment: AbiInitialCommitment,
    pub seeds_exchange_commitment: AbiSeedExchangeCommitment,
}

#[derive(Debug)]
pub struct AbiDvtShare {
    pub id: [u8; BLS_ID_SIZE],
    pub pubkey: [u8; BLS_PUBKEY_SIZE],
}

#[derive(Debug)]
pub struct AbiDvtData {
    pub settings: DvtGenerateSettings,
    pub verification_vectors: Vec<AbiVerificationVector>,
    pub shares: Vec<AbiDvtShare>,
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
            src_id: decode_hex::<BLS_ID_SIZE>(&self.src_id).map_err(|e| format!("Invalid id: {}", e))?,
            dst_id: decode_hex::<BLS_ID_SIZE>(&self.dst_id).map_err(|e| format!("Invalid id: {}", e))?,
            secret: decode_hex::<BLS_SECRET_SIZE>(&self.secret)
                .map_err(|e| format!("Invalid secret: {}", e))?,
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

pub fn read_share_data_from_file(filename: &str) -> Result<DvtBlsSharedData, Box<dyn Error>> {
    let mut file = File::open(filename).map_err(|e| format!("Error opening file: {}", e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Error reading file: {}", e))?;

    let data: DvtBlsSharedData = serde_json::from_str(&contents)?;
    Ok(data)
}
