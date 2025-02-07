use dvt_abi::{self};
use sp1_zkvm;

fn read_byte_array_from_host<const N: usize>() -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = sp1_zkvm::io::read();
    }
    result
}

trait ReadFromHost: Sized {
    fn read_from_host() -> Self;
}

impl ReadFromHost for dvt_abi::BLSPubkey {
    fn read_from_host() -> dvt_abi::BLSPubkey {
        read_byte_array_from_host::<{ dvt_abi::BLS_PUBKEY_SIZE }>()
    }
}

impl ReadFromHost for dvt_abi::SHA256 {
    fn read_from_host() -> dvt_abi::SHA256 {
        read_byte_array_from_host::<{ dvt_abi::SHA256_SIZE }>()
    }
}

fn read_vec_from_host<T: ReadFromHost>(cnt: u8) -> Vec<T> {
    let mut result = Vec::with_capacity(cnt as usize);
    for _ in 0..cnt {
        result.push(T::read_from_host());
    }
    result
}

fn read_gen_id_from_host() -> [u8; dvt_abi::GEN_ID_SIZE] {
    read_byte_array_from_host::<{ dvt_abi::GEN_ID_SIZE }>()
}

fn read_pubkey_from_host() -> dvt_abi::BLSPubkey {
    read_byte_array_from_host::<{ dvt_abi::BLS_PUBKEY_SIZE }>()
}

fn read_signature_from_host() -> dvt_abi::BLSSignature {
    read_byte_array_from_host::<{ dvt_abi::BLS_SIGNATURE_SIZE }>()
}

fn read_secret_from_host() -> dvt_abi::BLSSecret {
    read_byte_array_from_host::<{ dvt_abi::BLS_SECRET_SIZE }>()
}

fn read_bls_id_from_host() -> dvt_abi::BLSId {
    read_byte_array_from_host::<{ dvt_abi::BLS_ID_SIZE }>()
}

fn read_hash_from_host() -> dvt_abi::SHA256 {
    read_byte_array_from_host::<{ dvt_abi::SHA256_SIZE }>()
}

fn read_byte_vec_from_host() -> Vec<u8> {
    let len = sp1_zkvm::io::read();
    let mut result = Vec::with_capacity(len as usize);
    for _ in 0..len {
        result.push(sp1_zkvm::io::read());
    }
    result
}

fn read_settings_from_host() -> dvt_abi::AbiGenerateSettings {
    dvt_abi::AbiGenerateSettings {
        n: sp1_zkvm::io::read(),
        k: sp1_zkvm::io::read(),
        gen_id: read_gen_id_from_host(),
    }
}

fn read_verification_vector_from_host(k: u8) -> dvt_abi::AbiVerificationVector {
    dvt_abi::AbiVerificationVector {
        pubkeys: read_vec_from_host(k),
    }
}

fn read_commitment_from_host() -> dvt_abi::AbiCommitment {
    dvt_abi::AbiCommitment {
        hash: read_hash_from_host(),
        pubkey: read_pubkey_from_host(),
        signature: read_signature_from_host(),
    }
}

fn read_initial_commitment_from_host() -> dvt_abi::AbiInitialCommitment {
    let hash = read_hash_from_host();
    let settings = read_settings_from_host();
    let verification_vector = read_verification_vector_from_host(settings.k);
    dvt_abi::AbiInitialCommitment {
        hash: hash,
        settings: settings,
        verification_vector: verification_vector,
    }
}

fn read_exchange_secret_from_host() -> dvt_abi::AbiExchangedSecret {
    dvt_abi::AbiExchangedSecret {
        src_id: read_bls_id_from_host(),
        dst_id: read_bls_id_from_host(),
        secret: read_secret_from_host(),
        dst_base_hash: read_hash_from_host(),
    }
}

fn read_seeds_exchange_commitment_from_host() -> dvt_abi::AbiSeedExchangeCommitment {
    let initial_commitment_hash = read_hash_from_host();
    let shared_secret = read_exchange_secret_from_host();
    let commitment = read_commitment_from_host();
    dvt_abi::AbiSeedExchangeCommitment {
        initial_commitment_hash: initial_commitment_hash,
        shared_secret: shared_secret,
        commitment: commitment,
    }
}

fn read_generation_data(n: u8, k: u8) -> Vec<dvt_abi::AbiGeneration> {
    let mut result = Vec::new();
    for _ in 0..n {
        let verification_vector = read_vec_from_host(k);
        let base_hash = read_hash_from_host();
        let partial_pubkey = read_pubkey_from_host();
        let message = read_byte_vec_from_host();
        let message_signature = read_signature_from_host();

        result.push(dvt_abi::AbiGeneration {
            verification_vector: verification_vector,
            base_hash: base_hash,
            partial_pubkey: partial_pubkey,
            message_cleartext: message,
            message_signature: message_signature,
        });
    }
    result
}

pub fn read_bls_shared_data_from_host() -> dvt_abi::AbiBlsSharedData {
    let inital_commitment = read_initial_commitment_from_host();
    let seeds_exchange_commitment = read_seeds_exchange_commitment_from_host();
    let verification_hashes = read_vec_from_host(inital_commitment.settings.n);
    dvt_abi::AbiBlsSharedData {
        verification_hashes: verification_hashes,
        initial_commitment: inital_commitment,
        seeds_exchange_commitment: seeds_exchange_commitment,
    }
}

pub fn read_finalization_data() -> dvt_abi::AbiFinalizationData {
    let settings = read_settings_from_host();
    let generations = read_generation_data(settings.n, settings.k);
    let aggregate_pubkey = read_pubkey_from_host();
    dvt_abi::AbiFinalizationData {
        settings: settings,
        generations: generations,
        aggregate_pubkey: aggregate_pubkey,
    }
}

pub fn read_wrong_final_key_generation_data() -> dvt_abi::AbiWrongFinalKeyGeneration {
    let settings = read_settings_from_host();
    let generations = read_generation_data(settings.n, settings.k);
    let perpatrator_hash = read_hash_from_host();
    dvt_abi::AbiWrongFinalKeyGeneration {
        settings: settings,
        generations: generations,
        perpatrator_hash: perpatrator_hash,
    }
}
