use sp1_sdk::{SP1Stdin};
use dvt_abi::AbiBlsSharedData;
fn write_array_to_prover<const N: usize>(stdin: &mut SP1Stdin, data: &[u8; N]) {
    for i in 0..N {
        stdin.write(&[data[i]]);
    }
}

pub fn abi_bls_share_data_write_to_prover(stdin: &mut SP1Stdin, data: &AbiBlsSharedData) {
    assert!(data.settings.k + 1== data.verification_vector.pubkeys.len() as u32);
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