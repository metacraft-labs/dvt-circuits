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
    let data: dkg::SharedData<Setup> =
        serde_cbor::from_slice(&input).expect("Failed to deserialize share data");

    if data.verification_hashes.len() != data.initial_commitment.settings.n as usize {
        panic!("The number of verification hashes does not match the number of keys\n");
    }

    if data.initial_commitment.settings.n < data.initial_commitment.settings.k {
        panic!("N should be greater than or equal to k\n");
    }

    let found = data
        .verification_hashes
        .iter()
        .any(|h| h == &data.initial_commitment.hash);

    if !found {
        panic!("The seed exchange commitment is not part of the verification hashes\n");
    }

    if !dkg::verify_initial_commitment_hash::<Setup>(&data.initial_commitment) {
        panic!("Unsalshable error while verifying commitment hash\n");
    }

    match dkg::verify_seed_exchange_commitment::<Setup>(
        &data.verification_hashes,
        &data.seeds_exchange_commitment,
        &data.initial_commitment,
    ) {
        Ok(()) => {
            println!("The share is valid. We can't prove participant share is corrupted.");
        }

        Err(e) => {
            if let Some(verification_error) = e.downcast_ref::<VerificationErrors>() {
                match verification_error {
                    VerificationErrors::SlashableError(err) => {
                        println!("Slashable error seed exchange commitment: {}", err);

                        for h in data.verification_hashes.iter() {
                            println!("Verification hash: {}", h);
                            sp1_zkvm::io::commit(&h);
                        }

                        println!(
                            "Perpetrator public key: {}",
                            data.seeds_exchange_commitment.commitment.pubkey
                        );
                        sp1_zkvm::io::commit(&data.seeds_exchange_commitment.commitment.pubkey);
                        return;
                    }
                    VerificationErrors::UnslashableError(err) => {
                        panic!("Unslashable error seed exchange commitment:\n {}", err);
                    }
                }
            } else {
                panic!("Unknown error seed exchange commitment: {}", e);
            }
        }
    }
    panic!("The seed exchange commitment is valid");
}
