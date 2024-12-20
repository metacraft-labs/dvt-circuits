#![no_main]

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar,
};
use dvt_abi::{AbiBlsSharedData, AbiVerificationVector, DvtGenerateSettings};
use sha2::{Digest, Sha256};
use std::ptr::hash;
sp1_zkvm::entrypoint!(main);

use bls_utils::{bls_verify, evaluate_polynomial, validate_verification_data};

pub fn read_array_from_host<const N: usize>() -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = sp1_zkvm::io::read();
    }
    result
}

pub fn read_pubkeys_from_host(cnt: u32) -> Vec<[u8; 48]> {
    let mut result = Vec::new();
    for i in 0..cnt {
        result.push(read_array_from_host());
    }
    result
}

pub fn abi_bls_share_data_read_from_host() -> AbiBlsSharedData {
    let settings = DvtGenerateSettings {
        n: sp1_zkvm::io::read(),
        k: sp1_zkvm::io::read(),
    };

    let pubkeys = read_pubkeys_from_host(settings.k);
    let hash = read_array_from_host::<32>();
    let signature = read_array_from_host::<96>();
    let creator_pubkey = read_array_from_host::<48>();
    let target = read_array_from_host::<48>();
    let id = read_array_from_host::<32>();
    AbiBlsSharedData {
        settings: settings,
        verification_vector: AbiVerificationVector {
            hash: hash,
            pubkeys: pubkeys,
            creator_pubkey: creator_pubkey,
            signature: signature,
        },
        target: target,
        id: id,
    }
}



pub fn main() {
    let data = abi_bls_share_data_read_from_host();

    let ok = validate_verification_data(&data.verification_vector);
    if ok.is_err() {
        print!("Invalid verification vector {}\n", ok.err().unwrap());
        panic!();
    }

    let verification_vector: Vec<G1Affine> = data
        .verification_vector
        .pubkeys
        .iter()
        .map(|pk: &[u8; 48]| G1Affine::from_compressed(&pk).into_option().unwrap())
        .collect();

    let result = evaluate_polynomial(verification_vector, Scalar::from_bytes(&data.id).unwrap());
    if result
        == G1Affine::from_compressed(&data.target)
            .into_option()
            .unwrap()
    {
        print!("Good \n")
    } else {
        print!("Bad \n");
        panic!();
    }
}

