#![no_main]

use std::ptr::hash;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve}, pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar
    
};
use dvt_abi::{AbiBlsSharedData, AbiVerificationVector, DvtGenerateSettings};
use sha2::{Sha256, Digest};
sp1_zkvm::entrypoint!(main);

use bls_utils::{evaluate_polynomial, bls_verify};

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
    
    let pubkeys = read_pubkeys_from_host(settings.k + 1);
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

    let mut sign_data: Vec<u8> = Vec::new();
    for i in 0..data.verification_vector.pubkeys.len() {
        let mut o = data.verification_vector.pubkeys[i].as_slice().to_vec();
        sign_data.append(&mut o);
    }

    let mut hasher = Sha256::new();

    // Provide the data to hash
    hasher.update(&sign_data);

    // Retrieve the result
    let result = hasher.finalize();
    
    if result.to_vec() == data.verification_vector.hash {
        print!("Hash verified \n");
    } else {
        print!("Hash not verified \n");
        panic!();
    }

    let sig = G2Affine::from_compressed(&data.verification_vector.signature).into_option();
    let pk = G1Affine::from_compressed(&data.verification_vector.creator_pubkey).into_option();

    if bls_verify(&pk.unwrap(),&sig.unwrap(), &sign_data) {
        print!("Signature verified \n");
    } else {
        print!("Signature not verified \n");
        panic!();
    }


    let verification_vector : Vec<G1Affine> = data.verification_vector.pubkeys.iter()
    .map(|pk: &[u8; 48]|  G1Affine::from_compressed(&pk).into_option().unwrap())
    .collect();

    let result = evaluate_polynomial(verification_vector, Scalar::from_bytes(&data.id).unwrap());
    if result == G1Affine::from_compressed(&data.target).into_option().unwrap() {
        print!("Good \n")
    } else {
        print!("Bad \n");
        panic!();
    }
}
