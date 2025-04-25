#![no_main]

sp1_zkvm::entrypoint!(main);

use core::panic;

use dkg::crypto::*;
use dkg::types::*;
use dkg::{self, VerificationErrors};
use serde::Deserialize;

pub fn main() {
    run::<BlsDkgWithSecp256kCommitment>();
}

pub fn run<Setup>()
where
    Setup: dkg::DkgSetup + dkg::DkgSetupTypes<Setup> + for<'a> Deserialize<'a>,
{
    let input: Vec<u8> = sp1_zkvm::io::read();
    let data: dkg::BadPartialShareData<Setup> =
        serde_cbor::from_slice(&input).expect("Failed to deserialize share data");
    match dkg::prove_wrong_final_key_generation(&data) {
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
