use serde::Deserialize;

use std::fs::File;
use std::io::Read;
use hex::decode;

use std::error::Error;

const BLS_SIGNATURE_SIZE: usize = 96;
const BLS_PUBKEY_SIZE: usize = 48;
const BLS_ID_SIZE: usize = 32;
const SHA256_SIZE: usize = 32;


#[derive(Debug, Deserialize)]
pub struct VerificationVector {
    pub hash: String,
    pub signature: String,
    pub creator_pubkey: String,
    pub pubkey: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct DvtGenerateSettings {
    pub n: u32,
    pub k: u32,
}

#[derive(Debug, Deserialize)]
pub struct DvtData {
    pub settings: DvtGenerateSettings,
    pub verification_vectors: Vec<VerificationVector>,
    pub pubkeys: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct BlsSharedData {
    pub settings: DvtGenerateSettings,
    pub verification_vector: VerificationVector,
    pub target: String,
    pub id: String,
}

#[derive(Debug)]
pub struct AbiVerificationVector {
    pub hash: [u8; SHA256_SIZE],
    pub creator_pubkey: [u8; BLS_PUBKEY_SIZE],
    pub signature: [u8; BLS_SIGNATURE_SIZE],
    pub pubkeys: Vec<[u8; BLS_PUBKEY_SIZE]>,
}

#[derive(Debug)]
pub struct AbiBlsSharedData {
    pub settings: DvtGenerateSettings,
    pub verification_vector: AbiVerificationVector,
    pub target: [u8; BLS_PUBKEY_SIZE],
    pub id: [u8; BLS_ID_SIZE],
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

pub fn to_abi_verification_vector(data: &VerificationVector) -> Result<AbiVerificationVector, Box<dyn std::error::Error>> {
    let mut pubkeys = Vec::new();
    for (i, pubkey) in data.pubkey.iter().enumerate() {
        let key = decode_hex::<BLS_PUBKEY_SIZE>(pubkey)
            .map_err(|e| format!("Invalid key at index {}: {}", i, e))?;
        pubkeys.push(key);
    }

    let hash = decode_hex::<SHA256_SIZE>(&data.hash)
        .map_err(|e| format!("Invalid hash: {}", e))?;
    
    let creator_pubkey = decode_hex::<BLS_PUBKEY_SIZE>(&data.creator_pubkey)
        .map_err(|e| format!("Invalid creator public key: {}", e))?;
    
    let pubkeys_array = pubkeys.try_into()
        .map_err(|e| format!("Invalid keys length: {}", e))?;
    
    let signature = decode_hex::<BLS_SIGNATURE_SIZE>(&data.signature)
        .map_err(|e| format!("Invalid signature: {}", e))?;
    
    Ok(AbiVerificationVector {
        hash,
        creator_pubkey,
        pubkeys: pubkeys_array,
        signature,
    })
}
pub fn to_abi_bls_data(data: &BlsSharedData) -> Result<AbiBlsSharedData, Box<dyn Error>> {
    let verification_vector = to_abi_verification_vector(&data.verification_vector)
        .map_err(|e| format!("Invalid verification vector: {}", e))?;
    let target = decode_hex::<BLS_PUBKEY_SIZE>(&data.target)
        .map_err(|e| format!("Invalid target: {}", e))?;
    let id = decode_hex::<BLS_ID_SIZE>(&data.id)
        .map_err(|e| format!("Invalid id: {}", e))?;
    
    Ok(AbiBlsSharedData {
        settings: DvtGenerateSettings {
            n: data.settings.n, 
            k: data.settings.k,
        },
        verification_vector,
        target,
        id,
    })
}
pub fn read_dvt_data_from_file(filename: &str) -> Result<DvtData, Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let data: DvtData = serde_json::from_str(&contents)?;
    Ok(data)
}

pub fn read_share_data_from_file(filename: &str) -> Result<BlsSharedData, Box<dyn Error>> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let data: BlsSharedData = serde_json::from_str(&contents)?;
    Ok(data)
}