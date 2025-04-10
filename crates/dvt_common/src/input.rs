use crypto::{
    for_each_raw_type, BLSIdRaw, BLSPubkeyRaw, BLSSecretRaw, BLSSignatureRaw, SHA256Raw,
    BLS_ID_SIZE, BLS_PUBKEY_SIZE, BLS_SECRET_SIZE, BLS_SIGNATURE_SIZE, GEN_ID_SIZE, SHA256_SIZE,
};
use dvt_abi::{self, BlsCommitment};
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

macro_rules! define_read_from_host {
    ($name:ident, $size_const:ident) => {
        impl ReadFromHost for $name {
            fn read_from_host() -> $name {
                read_byte_array_from_host::<{ $size_const }>().into()
            }
        }
    };
}

fn read_from_host<T>() -> T
where
    T: ReadFromHost,
{
    T::read_from_host()
}

for_each_raw_type!(define_read_from_host);

// impl ReadFromHost for SHA256Raw {
//     fn read_from_host() -> SHA256Raw {
//         read_byte_array_from_host::<{ SHA256_SIZE }>()
//     }
// }

fn read_vec_from_host<T: ReadFromHost>(cnt: u8) -> Vec<T> {
    let mut result = Vec::with_capacity(cnt as usize);
    for _ in 0..cnt {
        result.push(T::read_from_host());
    }
    result
}

// fn read_gen_id_from_host() -> [u8; GEN_ID_SIZE] {
//     read_byte_array_from_host::<{ GEN_ID_SIZE }>()
// }

// fn read_pubkey_from_host() -> BLSPubkeyRaw {
//     read_byte_array_from_host::<{ BLS_PUBKEY_SIZE }>()
// }

// fn read_signature_from_host() -> BLSSignatureRaw {
//     read_byte_array_from_host::<{ BLS_SIGNATURE_SIZE }>()
// }

// fn read_secret_from_host() -> BLSSecretRaw {
//     read_byte_array_from_host::<{ BLS_SECRET_SIZE }>()
// }

// fn read_bls_id_from_host() -> BLSIdRaw {
//     read_byte_array_from_host::<{ BLS_ID_SIZE }>()
// }

// fn read_hash_from_host() -> SHA256Raw {
//     read_byte_array_from_host::<{ SHA256_SIZE }>()
// }

fn read_byte_vec_from_host() -> Vec<u8> {
    let len = sp1_zkvm::io::read::<u32>();
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
        gen_id: read_byte_array_from_host::<{ GEN_ID_SIZE }>(),
    }
}

fn read_commitment_from_host() -> dvt_abi::AbiCommitment<BlsCommitment> {
    dvt_abi::AbiCommitment {
        hash: read_from_host(),
        pubkey: read_from_host(),
        signature: read_from_host(),
    }
}

fn read_initial_commitment_from_host() -> dvt_abi::AbiInitialCommitment {
    let hash = read_from_host();
    let settings = read_settings_from_host();
    let base_pubkeys = read_vec_from_host(settings.k);
    dvt_abi::AbiInitialCommitment {
        hash: hash,
        settings: settings,
        base_pubkeys: base_pubkeys,
    }
}

fn read_exchange_secret_from_host() -> dvt_abi::AbiExchangedSecret {
    dvt_abi::AbiExchangedSecret {
        secret: read_from_host(),
        dst_base_hash: read_from_host(),
    }
}

fn read_seeds_exchange_commitment_from_host() -> dvt_abi::AbiSeedExchangeCommitment {
    let initial_commitment_hash = read_from_host();
    let shared_secret = read_exchange_secret_from_host();
    let commitment = read_commitment_from_host();
    dvt_abi::AbiSeedExchangeCommitment {
        initial_commitment_hash: initial_commitment_hash,
        shared_secret: shared_secret,
        commitment: commitment,
    }
}

fn read_signle_generation(k: u8) -> dvt_abi::AbiGeneration {
    let verification_vector = read_vec_from_host(k);
    let base_hash = read_from_host();
    let partial_pubkey = read_from_host();
    let message = read_byte_vec_from_host();
    let message_signature = read_from_host();

    dvt_abi::AbiGeneration {
        verification_vector: verification_vector,
        base_hash: base_hash,
        partial_pubkey: partial_pubkey,
        message_cleartext: message,
        message_signature: message_signature,
    }
}

fn read_generation_data(n: u8, k: u8) -> Vec<dvt_abi::AbiGeneration> {
    let mut result = Vec::new();
    for _ in 0..n {
        result.push(read_signle_generation(k));
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
    let aggregate_pubkey = read_from_host();
    dvt_abi::AbiFinalizationData {
        settings: settings,
        generations: generations,
        aggregate_pubkey: aggregate_pubkey,
    }
}

fn read_partial_generation_data(n: u8, k: u8) -> Vec<dvt_abi::AbiBadPartialShareGeneration> {
    let mut result = Vec::new();
    for _ in 0..n {
        let verification_vector = read_vec_from_host(k);
        let base_hash = read_from_host();

        result.push(dvt_abi::AbiBadPartialShareGeneration {
            verification_vector: verification_vector,
            base_hash: base_hash,
        });
    }
    result
}

fn read_bad_partial_share() -> dvt_abi::AbiBadPartialShare {
    let settings = read_settings_from_host();
    let data = read_signle_generation(settings.k);
    let commitment = read_commitment_from_host();
    dvt_abi::AbiBadPartialShare {
        settings: settings,
        data: data,
        commitment: commitment,
    }
}

pub fn read_bad_partial_share_data() -> dvt_abi::AbiBadPartialShareData {
    let settings = read_settings_from_host();
    let generations = read_partial_generation_data(settings.n, settings.k);
    let bad_partial = read_bad_partial_share();
    dvt_abi::AbiBadPartialShareData {
        settings: settings,
        generations: generations,
        bad_partial: bad_partial,
    }
}

pub fn read_bad_encrypted_share() -> dvt_abi::AbiBadEncryptedShare {
    let sender_pubkey = read_from_host();
    let signature = read_from_host();
    let receiver_pubkey = read_from_host();
    let receiver_commitment_hash = read_from_host();
    let encrypted_message = read_byte_vec_from_host();
    let settings = read_settings_from_host();
    let base_hashes = read_vec_from_host::<SHA256Raw>(settings.n);
    let base_pubkeys = read_vec_from_host::<BLSPubkeyRaw>(settings.k);
    dvt_abi::AbiBadEncryptedShare {
        sender_pubkey: sender_pubkey,
        signature: signature,
        receiver_pubkey: receiver_pubkey,
        receiver_commitment_hash: receiver_commitment_hash,
        encrypted_message: encrypted_message,
        settings: settings,
        base_hashes: base_hashes,
        base_pubkeys: base_pubkeys,
    }
}
