use crypto::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateSettings {
    #[serde(rename = "n")]
    pub n: u8,
    #[serde(rename = "k")]
    pub k: u8,
    #[serde(rename = "gen_id")]
    pub gen_id: DvtGenId,
}

pub type AbiVerificationHashes = Vec<SHA256Raw>;

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
    pub verification_hashes: AbiVerificationHashes,
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
    pub base_hashes: AbiVerificationHashes,
    #[serde(rename = "base_pubkeys")]
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

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to generate a dummy SHA256Raw
    fn dummy_sha256() -> SHA256Raw {
        let mut arr = [0u8; SHA256_SIZE];
        for i in 0..arr.len() {
            arr[i] = i as u8;
        }
        SHA256Raw(arr)
    }

    // Helper to generate a dummy BLSPubkeyRaw
    fn dummy_blspubkey() -> BLSPubkeyRaw {
        let mut arr = [0u8; BLS_PUBKEY_SIZE];
        for i in 0..arr.len() {
            arr[i] = i as u8;
        }
        BLSPubkeyRaw(arr)
    }

    fn dummy_blssecret() -> BLSSecretRaw {
        let mut arr = [0u8; BLS_SECRET_SIZE];
        for i in 0..arr.len() {
            arr[i] = i as u8;
        }
        BLSSecretRaw(arr)
    }

    // Helper to generate a dummy BLSSignatureRaw
    fn dummy_blssignature() -> BLSSignatureRaw {
        let mut arr = [0u8; BLS_SIGNATURE_SIZE];
        for i in 0..arr.len() {
            arr[i] = i as u8;
        }
        BLSSignatureRaw(arr)
    }

    #[test]
    fn test_seed_echange_commitemnt() {
        let original = SeedExchangeCommitment {
            initial_commitment_hash: dummy_sha256(),
            shared_secret: ExchangedSecret {
                secret: dummy_blssecret(),
                dst_base_hash: dummy_sha256(),
            },
            commitment: Commitment {
                hash: dummy_sha256(),
                pubkey: dummy_blspubkey(),
                signature: dummy_blssignature(),
            },
        };

        // ----- JSON round-trip -----
        let json_str = serde_json::to_string(&original).expect("JSON serialization failed");
        println!("{}", json_str);
        let from_json: SeedExchangeCommitment =
            serde_json::from_str(&json_str).expect("JSON deserialization failed");
        assert_eq!(
            &original.initial_commitment_hash.0[..],
            &from_json.initial_commitment_hash.0[..],
            "Initial commitment hash mismatch after JSON round-trip"
        );
        assert_eq!(
            &original.shared_secret.secret.0[..],
            &from_json.shared_secret.secret.0[..],
            "Shared secret mismatch after JSON round-trip"
        );
        assert_eq!(
            &original.shared_secret.dst_base_hash.0[..],
            &from_json.shared_secret.dst_base_hash.0[..],
            "Destination base hash mismatch after JSON round-trip"
        )
    }

    #[test]
    fn test_abi_commitment_serialization() {
        // Create a dummy instance
        let original = Commitment::<BlsCommitment> {
            hash: dummy_sha256(),
            pubkey: dummy_blspubkey(),
            signature: dummy_blssignature(),
        };

        // ----- JSON round-trip -----
        let json_str = serde_json::to_string(&original).expect("JSON serialization failed");
        let from_json: Commitment<BlsCommitment> =
            serde_json::from_str(&json_str).expect("JSON deserialization failed");
        assert_eq!(
            &original.hash.0[..],
            &from_json.hash.0[..],
            "Hash mismatch after JSON round-trip"
        );
        assert_eq!(
            &original.pubkey.0[..],
            &from_json.pubkey.0[..],
            "Pubkey mismatch after JSON round-trip"
        );
        assert_eq!(
            &original.signature.0[..],
            &from_json.signature.0[..],
            "Signature mismatch after JSON round-trip"
        );

        // ----- CBOR round-trip -----
        let bin = serde_cbor::to_vec(&original).expect("CBOR serialization failed");
        let from_bin: Commitment<BlsCommitment> =
            serde_cbor::from_slice(&bin).expect("CBOR deserialization failed");
        assert_eq!(
            &original.hash.0[..],
            &from_bin.hash.0[..],
            "Hash mismatch after CBOR round-trip"
        );
        assert_eq!(
            &original.pubkey.0[..],
            &from_bin.pubkey.0[..],
            "Pubkey mismatch after CBOR round-trip"
        );
        assert_eq!(
            &original.signature.0[..],
            &from_bin.signature.0[..],
            "Signature mismatch after CBOR round-trip"
        );
    }
}
