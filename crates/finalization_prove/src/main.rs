#![no_main]

sp1_zkvm::entrypoint!(main);

use dkg::{BlsDkgWithBlsCommitment, ByteConvertible, DkgSetupTypes, TPoint, TScalar};

pub fn main() {
    let input: Vec<u8> = sp1_zkvm::io::read();
    let data: dkg::FinalizationData<BlsDkgWithBlsCommitment> =
        serde_cbor::from_slice(&input).expect("Failed to deserialize share data");

    let agg_key =
        <BlsDkgWithBlsCommitment as DkgSetupTypes<BlsDkgWithBlsCommitment>>::DkgPubkey::from_bytes(
            &data.aggregate_pubkey,
        )
        .expect("Invalid aggregated key");

    // Circuit 4: Verify final key reconstruction via Lagrange interpolation
    // The aggregate key should equal P(0) where P is the aggregated polynomial
    verify_final_key_reconstruction::<BlsDkgWithBlsCommitment>(
        &data.generations,
        &data.settings,
        &agg_key,
    )
    .expect("Final key reconstruction verification failed");

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

fn verify_final_key_reconstruction<Setup>(
    generations: &[dkg::Generation<Setup>],
    settings: &dkg::GenerateSettings,
    expected_agg_key: &Setup::DkgPubkey,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: dkg::DkgSetup + dkg::DkgSetupTypes<Setup>,
{
    if generations.len() != settings.n as usize {
        return Err("Invalid number of generations".into());
    }

    // Sort generations by base_hash to ensure deterministic ordering
    let mut sorted_generations = generations.to_vec();
    sorted_generations.sort_by(|a, b| a.base_hash.cmp(&b.base_hash));

    // Extract verification vectors and partial public keys
    let verification_vectors: Vec<Vec<Setup::Point>> = sorted_generations
        .iter()
        .map(|g| {
            g.verification_vector
                .iter()
                .map(|pt| Setup::Point::from_bytes(pt).expect("Invalid point"))
                .collect()
        })
        .collect();

    let partial_pubkeys: Vec<Setup::Point> = sorted_generations
        .iter()
        .map(|g| Setup::Point::from_bytes(&g.partial_pubkey).expect("Invalid partial pubkey"))
        .collect();

    // Create participant IDs (1-based indexing as per spec)
    let ids: Vec<Setup::Scalar> = (1..=generations.len())
        .map(|i| Setup::Scalar::from_u32(i as u32))
        .collect();

    // Method 1: Compute P(0) directly as the constant term of aggregated polynomial
    // P(x) = Σ_{j=0}^t c_j x^j where c_j = Σ_{k=1}^n PK(a_{k,j})
    // P(0) = c_0 = Σ_{k=1}^n PK(a_{k,0})

    // Extract constant terms for batch addition
    let constant_terms: Vec<Setup::Point> = verification_vectors.iter().map(|v| v[0]).collect();

    // Use optimized batch addition
    let p0 = dkg::batch_add_points::<Setup::Curve>(&constant_terms);

    // Method 2: Use Lagrange interpolation on partial public keys (spec requirement)
    // L(PK_1, ..., PK_n) should equal P(0)
    let interpolated_key = lagrange_interpolation_at_zero::<Setup::Curve>(&partial_pubkeys, &ids)?;

    // Verify that both methods give the same result and match expected aggregate key
    if p0.to_bytes() != interpolated_key.to_bytes() {
        return Err("Direct P(0) computation does not match Lagrange interpolation result".into());
    }

    if p0.to_bytes() != expected_agg_key.to_bytes() {
        return Err("Computed P(0) does not match expected aggregate key".into());
    }

    Ok(())
}

fn lagrange_interpolation_at_zero<C: dkg::Curve>(
    y_vec: &[C::Point],
    x_vec: &[C::Scalar],
) -> Result<C::Point, Box<dyn std::error::Error>> {
    let k = x_vec.len();
    if k == 0 || k != y_vec.len() {
        return Err("invalid inputs".into());
    }
    if k == 1 {
        return Ok(y_vec[0].clone());
    }

    // We calculate L(0) - evaluate Lagrange interpolation at x=0
    // For each point (x_i, y_i), compute the Lagrange basis polynomial l_i(0)
    // l_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j) = Π_{j≠i} (-x_j) / (x_i - x_j)

    // Pre-allocate vectors for batch processing
    let mut terms = Vec::with_capacity(k);

    for i in 0..k {
        let mut numerator = C::Scalar::from_u32(1); // This will be Π_{j≠i} (-x_j)
        let mut denominator = C::Scalar::from_u32(1); // This will be Π_{j≠i} (x_i - x_j)

        for j in 0..k {
            if j != i {
                // numerator *= -x_j
                let neg_xj = C::Scalar::from_u32(0).sub(&x_vec[j]);
                numerator = numerator.mul(&neg_xj);

                // denominator *= (x_i - x_j)
                let x_diff = x_vec[i].sub(&x_vec[j]);
                denominator = denominator.mul(&x_diff);
            }
        }

        let li0 = numerator.mul(&denominator.invert());
        let term = y_vec[i].mul_scalar(&li0);
        terms.push(term);
    }

    // Batch add all terms instead of accumulating sequentially
    Ok(dkg::batch_add_points::<C>(&terms))
}
