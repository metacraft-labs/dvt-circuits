#![no_main]

use std::ptr::hash;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve}, pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar
    
};
use dvt_abi::{AbiBlsSharedData, AbiVerificationVector, DvtGenerateSettings};
use sha2::Sha256;
sp1_zkvm::entrypoint!(main);

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


pub fn hash_message_to_g2(msg: &[u8], domain: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msg], domain)
}

pub fn bls_verify(
    pubkey: &G1Affine,
    signature: &G2Affine,
    message: &[u8]
) -> bool {

    let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let pk_projective = G1Projective::from(pubkey);
    let sig_projective = G2Projective::from(signature);

    let hashed_msg = hash_message_to_g2(message, domain);
    let left = pairing(&G1Affine::from(pk_projective), &G2Affine::from(hashed_msg));
    let right = pairing(&G1Affine::generator(), &G2Affine::from(sig_projective));

    left == right
}
fn evaluate_polynomial(cfs: Vec<G1Affine>, x: Scalar) -> G1Affine {

    let cfst: Vec<G1Projective> = cfs.iter().map(|c| G1Projective::from(c)).collect();
    let count = cfst.len();
    if count == 0 {
        return G1Affine::identity();
    } else if count == 1 {
        return cfs[0];
    } else {       
        let mut y = cfst[count - 1];
        for i in 2..(count+1) {
            y = y * x + cfs[count - i];
        }
        return G1Affine::from(y);
    }    
}

pub fn main() {

    let data = abi_bls_share_data_read_from_host();

    let mut sign_data: Vec<u8> = Vec::new();
    for i in 0..data.verification_vector.pubkeys.len() {
        let mut o = data.verification_vector.pubkeys[i].as_slice().to_vec();
        sign_data.append(&mut o);
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
