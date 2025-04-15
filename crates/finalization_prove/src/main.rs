#![no_main]

sp1_zkvm::entrypoint!(main);

use dvt::crypto::HexConvertable;

pub fn main() {
    let input: Vec<u8> = sp1_zkvm::io::read();
    let data: dvt::FinalizationData =
        serde_cbor::from_slice(&input).expect("Failed to deserialize share data");
    let ok = dvt::verify_generations(&data.generations, &data.settings, &data.aggregate_pubkey);
    if ok.is_err() {
        panic!("{:?}", ok.unwrap_err().to_string());
    }

    for g in data.generations.iter() {
        println!("Verification hash: {}", g.base_hash);
        sp1_zkvm::io::commit(g.base_hash.as_ref());
    }

    println!("Aggregate pubkey: {}", data.aggregate_pubkey);
    for byte in data.aggregate_pubkey.iter() {
        sp1_zkvm::io::commit(byte);
    }
}
