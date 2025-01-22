#![no_main]

sp1_zkvm::entrypoint!(main);

use bls12_381::G1Affine;

use bls_utils;

pub fn main() {
    let data = bls_utils::read_finalization_data();
    let ok =
        bls_utils::verify_generations(&data.generations, &data.settings, &data.aggregate_pubkey);
    if ok.is_err() {
        panic!("{:?}", ok.unwrap_err().to_string());
    }
}
