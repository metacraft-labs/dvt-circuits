#![no_main]

sp1_zkvm::entrypoint!(main);

use crypto::*;
use dvt_common;

pub fn main() {
    let data = dvt_common::read_finalization_data();
    let ok =
        dvt_common::verify_generations(&data.generations, &data.settings, &data.aggregate_pubkey);
    if ok.is_err() {
        panic!("{:?}", ok.unwrap_err().to_string());
    }

    for g in data.generations.iter() {
        println!("Verification hash: {}", g.base_hash.to_hex());
        sp1_zkvm::io::commit(g.base_hash.as_ref());
    }

    println!("Aggregate pubkey: {}", data.aggregate_pubkey.to_hex());
    for byte in data.aggregate_pubkey.iter() {
        sp1_zkvm::io::commit(byte);
    }
}
