#![no_main]

sp1_zkvm::entrypoint!(main);

use core::panic;

use bls_utils::{self, VerificationErrors};

pub fn main() {
    let data = bls_utils::read_bad_partial_share_data();
    println!("{:?}", data);

    match bls_utils::prove_wrong_final_key_generation(&data) {
        Ok(()) => {
            panic!("Can't prove wrong doing");
        }
        Err(e) => {
            if let Some(verification_error) = e.downcast_ref::<VerificationErrors>() {
                match verification_error {
                    VerificationErrors::SlashableError(e) => {
                        for h in data.generations.iter() {
                            println!("Verification hash: {}", hex::encode(h.base_hash));
                            sp1_zkvm::io::commit(&h.base_hash);
                        }

                        println!(
                            "Perpetrator public key: {}",
                            hex::encode(data.bad_partial.commitment.pubkey)
                        );
                        for byte in data.bad_partial.commitment.pubkey {
                            sp1_zkvm::io::commit(&byte);
                        }
                        return;
                    }
                    VerificationErrors::UnslashableError(e) => {
                        panic!("Unslashable error while proving: {}", e);
                    }
                }
            }
        }
    }
    panic!("Can't prove wrong doing");
}
