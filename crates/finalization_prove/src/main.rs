#![no_main]

sp1_zkvm::entrypoint!(main);

use bls_utils;

pub fn main() {
    let data = bls_utils::read_finalization_data();
    let ok =
        bls_utils::verify_generations(&data.generations, &data.settings, &data.aggregate_pubkey);
    if ok.is_err() {
        panic!("{:?}", ok.unwrap_err().to_string());
    }

    for g in data.generations.iter() {
        println!("Verification hash: {}", hex::encode(&g.base_hash));
        sp1_zkvm::io::commit(&g.base_hash);
    }

    println!("Aggregate pubkey: {}", hex::encode(&data.aggregate_pubkey));
    for byte in data.aggregate_pubkey.iter() {
        sp1_zkvm::io::commit(byte);
    }
}
