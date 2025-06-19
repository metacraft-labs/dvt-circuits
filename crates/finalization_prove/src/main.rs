#![no_main]

sp1_zkvm::entrypoint!(main);

use dkg::{AsByteArr, BlsDkgWithBlsCommitment, ByteConvertible, DkgSetupTypes};

pub fn main() {
    let input: Vec<u8> = sp1_zkvm::io::read();
    let data: dkg::FinalizationData<BlsDkgWithBlsCommitment> =
        serde_cbor::from_slice(&input).expect("Failed to deserialize share data");

    let agg_key =
        <BlsDkgWithBlsCommitment as DkgSetupTypes<BlsDkgWithBlsCommitment>>::DkgPubkey::from_bytes(
            &data.aggregate_pubkey,
        )
        .expect("Invalid aggregated key");
    let ok = dkg::verify_generations::<BlsDkgWithBlsCommitment>(
        &data.generations,
        &data.settings,
        &agg_key,
    );
    if ok.is_err() {
        panic!("{:?}", ok.unwrap_err().to_string());
    }

    for g in data.generations.iter() {
        println!("Verification hash: {}", g.base_hash);
        sp1_zkvm::io::commit(&g.base_hash);
    }

    println!("Aggregate pubkey: {}", data.aggregate_pubkey);
    sp1_zkvm::io::commit(&data.aggregate_pubkey);
}
