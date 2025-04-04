#![no_main]

sp1_zkvm::entrypoint!(main);

use core::panic;

use dvt_common::{self, VerificationErrors};

pub fn main() {
    let data = dvt_common::read_bls_shared_data_from_host();

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

    if !dvt_common::verify_initial_commitment_hash(&data.initial_commitment) {
        panic!("Unsalshable error while verifying commitment hash\n");
    }

    match dvt_common::verify_seed_exchange_commitment(
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
                            println!("Verification hash: {}", hex::encode(h));
                            sp1_zkvm::io::commit(h);
                        }

                        println!(
                            "Perpetrator public key: {}",
                            hex::encode(data.seeds_exchange_commitment.commitment.pubkey)
                        );
                        for byte in data.seeds_exchange_commitment.commitment.pubkey {
                            sp1_zkvm::io::commit(&byte);
                        }

                        return;
                    }
                    VerificationErrors::UnslashableError(err) => {
                        panic!("Unslashable error seed exchange commitment: {}", err);
                    }
                }
            } else {
                panic!("Unknown error seed exchange commitment: {}", e);
            }
        }
    }
    panic!("The seed exchange commitment is valid");
}
