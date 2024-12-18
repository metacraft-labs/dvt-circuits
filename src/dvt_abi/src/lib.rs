use serde::Deserialize;
use std::fs::File;
use std::io::Read;
use hex::{decode, FromHexError};

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

fn decode_hex<const N: usize>(input: &str) -> Result<[u8; N], FromHexError> {
    let bytes = decode(input)?;

    // Check the length
    if bytes.len() != N {
        return Err(FromHexError::InvalidStringLength);
    }

    let mut arr = [0u8; N];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

pub fn to_abi_verification_vector(data: &VerificationVector) -> Result<AbiVerificationVector, FromHexError> {
    let mut pubkeys = Vec::new();
    for i in 0..data.pubkey.len() {
        let key= decode_hex::<BLS_PUBKEY_SIZE>(&data.pubkey[i])?;
        pubkeys.push(key);
    }
    Ok(AbiVerificationVector {
        hash: decode_hex::<SHA256_SIZE>(&data.hash)?,
        creator_pubkey: decode_hex::<BLS_PUBKEY_SIZE>(&data.creator_pubkey)?,
        pubkeys: pubkeys.try_into().unwrap(),
        signature: decode_hex::<BLS_SIGNATURE_SIZE>(&data.signature)?,
    })
}

pub fn to_abi_bls_data(data: &BlsSharedData) -> Result<AbiBlsSharedData, FromHexError> {
    Ok(AbiBlsSharedData {
        settings: DvtGenerateSettings {
            n: data.settings.n, 
            k: data.settings.k
        },
        verification_vector: to_abi_verification_vector(&data.verification_vector).expect("Invalid verification vector"),
        target: decode_hex::<BLS_PUBKEY_SIZE>(&data.target).expect("Invalid target"),
        id: decode_hex::<BLS_ID_SIZE>(&data.id).expect("Invalid id"),
    })
}

pub fn read_dvt_data_from_file(filename: &str) -> Result<DvtData, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let data: DvtData = serde_json::from_str(&contents)?;
    Ok(data)
}

pub fn read_share_data_from_file(filename: &str) -> Result<BlsSharedData, Box<dyn std::error::Error>> {
    let mut file = File::open(filename)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let data: BlsSharedData = serde_json::from_str(&contents)?;
    Ok(data)
}