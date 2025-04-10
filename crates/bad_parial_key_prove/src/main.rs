#![no_main]

sp1_zkvm::entrypoint!(main);

use core::panic;

use crypto::*;
use dvt_common::{self, VerificationErrors};

pub fn main() {
    let data = dvt_common::read_bad_partial_share_data();
    match dvt_common::prove_wrong_final_key_generation(&data) {
        Ok(()) => {
            panic!("Can't prove wrong doing");
        }
        Err(e) => {
            if let Some(verification_error) = e.downcast_ref::<VerificationErrors>() {
                match verification_error {
                    VerificationErrors::SlashableError(e) => {
                        for h in data.generations.iter() {
                            println!("Verification hash: {}", h.base_hash.to_hex());
                            sp1_zkvm::io::commit(h.base_hash.as_ref());
                        }

                        println!(
                            "Perpetrator public key: {}",
                            data.bad_partial.commitment.pubkey.to_hex()
                        );
                        for byte in data.bad_partial.commitment.pubkey.as_arr().iter() {
                            sp1_zkvm::io::commit(&byte);
                        }
                        return;
                    }
                    VerificationErrors::UnslashableError(e) => {
                        panic!("Unslashable error while proving: {e}");
                    }
                }
            }
        }
    }
    panic!("Can't prove wrong doing");
}
