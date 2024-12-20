#![no_main]

use dvt_abi::{AbiDvtData, AbiDvtShare, AbiVerificationVector, DvtGenerateSettings};
sp1_zkvm::entrypoint!(main);

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve}, pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar   
};

use bls_utils::{evaluate_polynomial, bls_verify, validate_verification_data};



pub fn read_array_from_host<const N: usize>() -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = sp1_zkvm::io::read();
    }
    result
}

pub fn read_pubkeys_from_host(cnt: u32) -> Vec<[u8; 48]> {
    let mut result = Vec::new();
    for _i in 0..cnt {
        result.push(read_array_from_host());
    }
    result
}


fn read_verification_vectors_from_host(n: u32, k: u32) -> Vec<AbiVerificationVector> {
    let mut verification_vectors = Vec::new();
    for _ in 0..n {
        verification_vectors.push(AbiVerificationVector {
            hash: read_array_from_host::<32>(),
            creator_pubkey: read_array_from_host::<48>(),
            pubkeys: read_pubkeys_from_host(k),
            signature: read_array_from_host::<96>(),
        });
    }
    verification_vectors
}

fn read_shares_from_host(k: u32) -> Vec<AbiDvtShare> {
    let mut shares = Vec::new();
    for _ in 0..k {
        shares.push(AbiDvtShare {
            id: read_array_from_host::<32>(),
            pubkey: read_array_from_host::<48>(),
        });
    }
    shares
}

fn read_from_host_abi_dvt_data() -> AbiDvtData {
    let settings = DvtGenerateSettings {
        n: sp1_zkvm::io::read(),
        k: sp1_zkvm::io::read(),
    };
    
    let verification_vectors = read_verification_vectors_from_host(settings.n, settings.k);
    let shares = read_shares_from_host(settings.n);
    AbiDvtData {
        settings: settings,
        verification_vectors: verification_vectors,
        shares: shares
    }
}

fn print_vec_g1_as_hex(v: Vec<G1Affine>) {
    for i in 0..v.len() {
        println!("{} ", hex::encode(v[i].to_compressed()));
    }
}

fn verify_dvt(data: &AbiDvtData) -> Result<(), Box<dyn std::error::Error>> {
    let verification_vectors: Vec<Vec<G1Affine>> = data.verification_vectors.iter().map(|vector| -> Vec<G1Affine> {
        vector
        .pubkeys
        .iter()
        .map(|pk: &[u8; 48]| G1Affine::from_compressed(&pk).into_option().unwrap())
        .collect()
    }).collect();


    let mut allPts = Vec::new();
    
    print!("n = {}, k = {}\n", data.settings.n, data.settings.k);
    print!("shares = {}, vectors = {}\n", data.shares.len(), verification_vectors.len());
    for i in 0..data.shares.len() {
        let mut pts = Vec::new();
        let share_id = Scalar::from_bytes(&data.shares[i].id).unwrap();
        for j in 0..verification_vectors.len() {
            let pt = evaluate_polynomial(verification_vectors[j].clone(), share_id);
            pts.push(pt);
        }
        allPts.push(pts);
    }

    print_vec_g1_as_hex(verification_vectors[0].clone());

    let mut final_keys =  Vec::new(); 

    print!("{}: \n", allPts.len());
    for i in 0..allPts.len() {
        let mut key: G1Affine = allPts[i][0];
        print!("{}: \n", allPts[i].len());
        for j in 1..allPts[i].len() {
            key = G1Affine::from(G1Projective::from(key) + G1Projective::from(allPts[i][j]));
        }
        final_keys.push(key);
    }

    print_vec_g1_as_hex(final_keys);

    Ok(())
}


fn verify_dvt_from_aggregate(data: &AbiDvtData) -> Result<(), Box<dyn std::error::Error>> {
    let verification_vectors: Vec<Vec<G1Affine>> = data.verification_vectors.iter().map(|vector| -> Vec<G1Affine> {
        vector
        .pubkeys
        .iter()
        .map(|pk: &[u8; 48]| G1Affine::from_compressed(&pk).into_option().unwrap())
        .collect()
    }).collect();


    
    print!("n = {}, k = {}\n", data.settings.n, data.settings.k);
    print!("shares = {}, vectors = {}\n", data.shares.len(), verification_vectors.len());
    print_vec_g1_as_hex(verification_vectors[0].clone());

    let mut final_keys =  Vec::new();
    for i in 0..data.shares.len() {
        let share_id = Scalar::from_bytes(&data.shares[i].id).unwrap();
        println!("{} ", hex::encode(share_id.to_bytes()));
        let pt = evaluate_polynomial(verification_vectors[0].clone(), share_id);
        final_keys.push(pt);
    }
    print_vec_g1_as_hex(final_keys);

    Ok(())
}

pub fn main() {

    let data = read_from_host_abi_dvt_data();

    // for i in 0..data.verification_vectors.len() {
    //     let ok = validate_verification_data(&data.verification_vectors[i]);
    //     if ok.is_err() {
    //         panic!("Invalid verification vector at index {}", i);
    //     }
    // }

    verify_dvt(&data).unwrap();
    //panic!();
}
