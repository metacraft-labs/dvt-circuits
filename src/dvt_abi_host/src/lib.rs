use sp1_sdk::{SP1Stdin};
use dvt_abi::{AbiBlsSharedData, AbiDvtData};
fn write_array_to_prover<const N: usize>(stdin: &mut SP1Stdin, data: &[u8; N]) {
    for i in 0..N {
        stdin.write(&[data[i]]);
    }
}

pub fn write_to_prover_abi_bls_share_data(stdin: &mut SP1Stdin, data: &AbiBlsSharedData) {
    assert!(data.settings.k== data.verification_vector.pubkeys.len() as u32);
    stdin.write(&[data.settings.n]);
    stdin.write(&[data.settings.k]);
    
    for i in 0..data.verification_vector.pubkeys.len() {
        write_array_to_prover(stdin, &data.verification_vector.pubkeys[i]);
    }

    write_array_to_prover(stdin, &data.verification_vector.hash);
    write_array_to_prover(stdin, &data.verification_vector.signature);
    write_array_to_prover(stdin, &data.verification_vector.creator_pubkey);
    write_array_to_prover(stdin, &data.target);
    write_array_to_prover(stdin, &data.id);
}


pub fn write_to_prover_abi_dvt_data(stdin: &mut SP1Stdin, data: &AbiDvtData) {
    stdin.write(&[data.settings.n]);
    stdin.write(&[data.settings.k]);
    
    for i in 0..data.verification_vectors.len() {
        let vector = &data.verification_vectors[i];
        write_array_to_prover(stdin, &vector.hash);
        write_array_to_prover(stdin, &vector.creator_pubkey);
        for j in 0..vector.pubkeys.len() {
            write_array_to_prover(stdin, &vector.pubkeys[j]);
        }
        write_array_to_prover(stdin, &vector.signature);
    }

    for i in 0..data.shares.len() {
        write_array_to_prover(stdin, &data.shares[i].id);
        write_array_to_prover(stdin, &data.shares[i].pubkey);
    }
}