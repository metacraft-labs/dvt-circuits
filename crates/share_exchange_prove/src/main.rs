#![no_main]


sp1_zkvm::entrypoint!(main);

use core::panic;

use bls_utils;

pub fn main() {
    let data = bls_utils::read_bls_shared_data_from_host();

    match bls_utils::verify_seed_exchange_commitment(&data.verification_hashes, &data.seeds_exchange_commitment, &data.initial_commitment) {
        bls_utils::ProveResult::SlashableError => {
            print!("Slashable error while verifying seed exchange commitment\n");
            return
        }
        bls_utils::ProveResult::UnslashableError => {
            print!("Unslashable error while verifying seed exchange commitment\n");
            panic!();
        }
        bls_utils::ProveResult::Ok => {
            print!("OK while verifying seed exchange commitment\n");
            
        }
    }

    match bls_utils::verify_initial_commitment(&data.initial_commitment) {
        bls_utils::ProveResult::SlashableError => {
            print!("Slashable error while verifying initial commitment\n");
            return
        }
        bls_utils::ProveResult::UnslashableError => {
            print!("Unslashable error while verifying initial commitment\n");
            panic!();
        }
        bls_utils::ProveResult::Ok => {
            print!("OK while verifying initial commitment\n");
            
        }
    }


    panic!("The seed exchange commitment is valid");

}

