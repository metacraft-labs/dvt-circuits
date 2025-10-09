use crate::crypto::{ByteConvertible, CryptoKeys, PublicKey, SecretKey};
use crate::traits::*;
use crate::types::*;
use sha2::{Digest, Sha256};

use crate::dkg_math::{agg_coefficients, evaluate_polynomial, lagrange_interpolation};

#[derive(Debug)]
pub enum VerificationErrors {
    SlashableError(String),
    UnslashableError(String),
}

impl std::fmt::Display for VerificationErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationErrors::SlashableError(e) => write!(f, "{}", e),
            VerificationErrors::UnslashableError(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for VerificationErrors {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(feature = "auth_commitment")]
pub fn compute_seed_exchange_hash<Setup>(seed_exchange: &SeedExchangeCommitment<Setup>) -> SHA256Raw
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let shared_secret = &seed_exchange.shared_secret;
    let mut hasher = Sha256::new();

    let sk = Setup::DkgSecretKey::from_bytes(&shared_secret.secret).expect("Invalid secret key");

    hasher.update(seed_exchange.initial_commitment_hash.as_ref());
    hasher.update(sk.to_bytes().as_arr());
    hasher.update(shared_secret.dst_base_hash.as_ref());

    hasher
        .finalize()
        .to_vec()
        .try_into()
        .expect("Can't produce SHA256")
}

pub fn get_index_in_commitments(
    commitments: &VerificationHashes,
    destination_id: &SHA256Raw,
) -> Result<u32, Box<dyn std::error::Error>> {
    let mut sorted = commitments.clone();
    sorted.sort();
    for (i, h) in sorted.iter().enumerate() {
        if h == destination_id {
            return Ok(i as u32);
        }
    }

    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Could not find destination in commitments",
    )))
}

#[cfg(feature = "auth_commitment")]
fn verify_commitment_details<Setup>(
    seed_exchange: &SeedExchangeCommitment<Setup>,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let commitment = &seed_exchange.commitment;

    if !verify_commitment(&seed_exchange.commitment) {
        return Err(Box::new(VerificationErrors::UnslashableError(format!(
            "Invalid field seeds_exchange_commitment.commitment.signature {},
                message: {}
                pubkey: {},
                \n",
            commitment.signature, commitment.hash, commitment.pubkey
        ))));
    }

    let computed_commitment_hash = compute_seed_exchange_hash::<Setup>(seed_exchange);

    if computed_commitment_hash.to_vec() != seed_exchange.commitment.hash.as_ref() {
        return Err(Box::new(VerificationErrors::SlashableError(
            format!(
                "Invalid field seeds_exchange_commitment.commitment.hash. Expected: {:?}, got hash: {:?}\n",
                seed_exchange.commitment.hash,
                hex::encode(computed_commitment_hash.to_vec())
            ),
        )));
    }

    Ok(())
}

fn validate_shared_secret<Setup>(
    seed_exchange: &SeedExchangeCommitment<Setup>,
) -> Result<Setup::DkgSecretKey, Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let shared_secret = &seed_exchange.shared_secret;
    Setup::DkgSecretKey::from_bytes(&shared_secret.secret).map_err(|e| {
        Box::new(VerificationErrors::SlashableError(format!(
            "Invalid field seeds_exchange_commitment.shared_secret.secret: {e} \n"
        ))) as Box<dyn std::error::Error>
    })
}

fn verify_polynomial_evaluation_for_seed<Setup>(
    verification_hashes: &VerificationHashes,
    seed_exchange: &SeedExchangeCommitment<Setup>,
    initial_commitment: &InitialCommitment<Setup>,
    sk: &Setup::DkgSecretKey,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let dest_id = get_index_in_commitments(
        verification_hashes,
        &seed_exchange.shared_secret.dst_base_hash,
    )
    .map_err(|e| {
        Box::new(VerificationErrors::SlashableError(format!(
            "Invalid field seeds_exchange_commitment.shared_secret.dst_base_hash: {e} \n"
        ))) as Box<dyn std::error::Error>
    })?;

    // F(0) is always reserved for the aggregated key so we need to start from 1
    let dest_id = dest_id + 1;
    let id = Setup::Scalar::from_u32(dest_id);

    let cfst: Vec<Setup::Point> = initial_commitment
        .base_pubkeys
        .iter()
        .map(Setup::Point::from_bytes)
        .map(|x| x.expect("Invalid pubkey"))
        .collect();

    let eval_result = evaluate_polynomial::<Setup::Curve>(&cfst, &id);
    if sk.to_public_key().to_bytes() != eval_result.to_bytes() {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Bad secret field : Expected secret with public key: {}, got public key: {}\n",
            eval_result,
            sk.to_public_key()
        ))));
    }

    Ok(())
}

pub fn verify_seed_exchange_commitment<Setup>(
    verification_hashes: &VerificationHashes,
    seed_exchange: &SeedExchangeCommitment<Setup>,
    initial_commitment: &InitialCommitment<Setup>,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    #[cfg(feature = "auth_commitment")]
    {
        verify_commitment_details(seed_exchange)?;
    }

    let sk = validate_shared_secret(seed_exchange)?;

    verify_polynomial_evaluation_for_seed(
        verification_hashes,
        seed_exchange,
        initial_commitment,
        &sk,
    )?;

    Ok(())
}

fn compute_base_hash<Setup>(
    settings: &GenerateSettings,
    pubkeys: &[RawBytes<Setup::Point>],
) -> Sha256
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let mut hasher = Sha256::new();

    hasher.update(settings.gen_id.as_ref());
    hasher.update([settings.n]);
    hasher.update([settings.k]);

    let len = pubkeys.len() as u8;
    hasher.update([len]);

    for pubkey in pubkeys {
        hasher.update(pubkey.as_arr());
    }

    hasher
}

pub fn compute_initial_commitment_hash<Setup>(
    settings: &GenerateSettings,
    base_pubkeys: &Vec<RawBytes<Setup::Point>>,
) -> SHA256Raw
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    compute_base_hash::<Setup>(settings, base_pubkeys)
        .finalize()
        .to_vec()
        .try_into()
        .expect("Vec must be exactly 32 bytes")
}

pub fn verify_initial_commitment_hash<Setup>(commitment: &InitialCommitment<Setup>) -> bool
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    compute_initial_commitment_hash::<Setup>(&commitment.settings, &commitment.base_pubkeys)
        == commitment.hash
}

fn generate_initial_commitment<Setup>(
    generation: &Generation<Setup>,
    settings: &GenerateSettings,
) -> InitialCommitment<Setup>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    InitialCommitment::<Setup> {
        hash: generation.base_hash,
        settings: GenerateSettings {
            n: settings.n,
            k: settings.k,
            gen_id: settings.gen_id,
        },
        base_pubkeys: generation.verification_vector.clone(),
    }
}

fn deserialize_verification_vectors<Setup>(
    generations: &[Generation<Setup>],
) -> Vec<Vec<Setup::Point>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    generations
        .iter()
        .map(|generation| -> Vec<Setup::Point> {
            generation
                .verification_vector
                .iter()
                .map(|pt| Setup::Point::from_bytes(pt).expect("Invalid point"))
                .collect()
        })
        .collect()
}

fn deserialize_bad_partial_share_verification_vectors<Setup>(
    generations: &[BadPartialShareGeneration<Setup>],
) -> Vec<Vec<Setup::Point>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    generations
        .iter()
        .map(|generation| -> Vec<Setup::Point> {
            generation
                .verification_vector
                .iter()
                .map(|pt| Setup::Point::from_bytes(pt).expect("Invalid point"))
                .collect()
        })
        .collect()
}

fn compute_agg_key_from_dkg<C: Curve>(
    verification_vectors: &[Vec<C::Point>],
    _ids: &[C::Scalar],
) -> Result<C::Point, Box<dyn std::error::Error>> {
    let coefficients = agg_coefficients::<C>(verification_vectors);
    if coefficients.is_empty() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no verification vectors",
        )));
    }
    Ok(coefficients[0])
}

fn verify_message_cleartext<Setup>(
    generations: &[Generation<Setup>],
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    if generations.is_empty() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid number of generations",
        )));
    }
    for i in 1..generations.len() {
        if generations[0].message_cleartext != generations[i].message_cleartext {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid message cleartext",
            )));
        }
    }
    Ok(())
}

fn verify_signatures_and_commitments<Setup>(
    generations: &[Generation<Setup>],
    settings: &GenerateSettings,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let message_mapping = Setup::TargetCryptography::precompute_message_mapping(
        generations[0].message_cleartext.as_bytes(),
    );

    for generation in generations.iter() {
        let signature = Setup::DkgSignature::from_bytes(&generation.message_signature)
            .expect("Invalid signature");
        let key =
            Setup::DkgPubkey::from_bytes(&generation.partial_pubkey).expect("Invalid public key");

        if !key.verify_signature_from_precomputed_mapping(&message_mapping, &signature) {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Invalid signature {}",
                generation.message_signature
            ))));
        }

        let initial_commitment = generate_initial_commitment(generation, settings);
        if !verify_initial_commitment_hash::<Setup>(&initial_commitment) {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Invalid initial commitment hash {}",
                initial_commitment.hash
            ))));
        }
    }
    Ok(())
}

pub fn verify_generation_hashes<Setup>(
    generations: &[Generation<Setup>],
    settings: &GenerateSettings,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    verify_message_cleartext(generations)?;
    verify_signatures_and_commitments(generations, settings)
}

fn sort_and_deserialize_vectors<Setup>(
    generations: &[Generation<Setup>],
) -> (Vec<Generation<Setup>>, Vec<Vec<Setup::Point>>)
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let mut sorted = generations.to_vec();
    sorted.sort_by(|a, b| a.base_hash.cmp(&b.base_hash));
    let verification_vectors = deserialize_verification_vectors::<Setup>(&sorted);
    (sorted, verification_vectors)
}

fn verify_computed_agg_key<Setup>(
    verification_vectors: &[Vec<Setup::Point>],
    ids: &[Setup::Scalar],
    agg_key: &Setup::DkgPubkey,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let computed_key = compute_agg_key_from_dkg::<Setup::Curve>(verification_vectors, ids)?;
    if agg_key.to_bytes() != computed_key.to_bytes() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Computed key {} does not match aggregate public key {}",
                computed_key, agg_key
            ),
        )));
    }
    Ok(())
}

fn verify_lagrange_interpolation_for_agg_key<Setup>(
    sorted_generations: &[Generation<Setup>],
    ids: &[Setup::Scalar],
    agg_key: &Setup::DkgPubkey,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let partial_keys: Vec<Setup::Point> = sorted_generations
        .iter()
        .map(|generation| {
            Setup::Point::from_bytes(&generation.partial_pubkey).expect("Invalid g1 point")
        })
        .collect();

    let computed_key = lagrange_interpolation::<Setup::Curve>(&partial_keys, ids)?;

    if computed_key.to_bytes() != agg_key.to_bytes() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Computed key {} does not match aggregate public key {}",
                computed_key, agg_key
            ),
        )));
    }
    Ok(())
}

pub fn verify_generations<Setup>(
    generations: &[Generation<Setup>],
    settings: &GenerateSettings,
    agg_key: &Setup::DkgPubkey,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    if generations.len() != settings.n as usize {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid number of generations",
        )));
    }

    verify_generation_hashes(generations, settings)?;

    let (sorted, verification_vectors) = sort_and_deserialize_vectors(generations);

    let ids: Vec<Setup::Scalar> = (1..=sorted.len())
        .map(|i| Setup::Scalar::from_u32(i as u32))
        .collect();

    verify_computed_agg_key::<Setup>(&verification_vectors, &ids, agg_key)?;
    verify_lagrange_interpolation_for_agg_key::<Setup>(&sorted, &ids, agg_key)?;

    Ok(())
}

#[cfg(feature = "auth_commitment")]
pub fn compute_partial_share_hash<Setup>(
    settings: &GenerateSettings,
    partial_share: &BadPartialShare<Setup>,
) -> Vec<u8>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let mut hasher = compute_base_hash::<Setup>(settings, &partial_share.data.verification_vector);

    hasher.update(partial_share.data.base_hash.as_ref());
    hasher.update(partial_share.data.partial_pubkey.as_arr());

    let len = partial_share.data.message_cleartext.len() as u8;
    hasher.update([len]);
    hasher.update(&partial_share.data.message_cleartext);
    hasher.update(partial_share.data.message_signature.as_arr());

    hasher.finalize().to_vec()
}

#[cfg(feature = "auth_commitment")]
pub fn verify_commitment<Setup>(commitment: &Commitment<Setup>) -> bool
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let key = Setup::CommitmentPubkey::from_bytes_safe(&commitment.pubkey)
        .unwrap_or_else(|_| panic!("Invalid pubkey {}", commitment.pubkey));
    let signature =
        Setup::CommitmentSignature::from_bytes(&commitment.signature).expect("Invalid signature");
    key.verify_signature(commitment.hash.as_ref(), &signature)
}

fn verify_generation_base_hashes<Setup>(
    data: &BadPartialShareData<Setup>,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    for generation in &data.generations {
        let initial_commitment = InitialCommitment::<Setup> {
            hash: generation.base_hash,
            settings: data.settings.clone(),
            base_pubkeys: generation.verification_vector.clone(),
        };

        if !verify_initial_commitment_hash::<Setup>(&initial_commitment) {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Invalid generation base hash {}",
                generation.base_hash
            ))));
        }
    }
    Ok(())
}

fn verify_expected_key<Setup>(
    sorted_generation: &[BadPartialShareGeneration<Setup>],
    perpetrator_index: usize,
    key: &Setup::DkgPubkey,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let perpetrator_id = Setup::Scalar::from_u32((perpetrator_index + 1) as u32);
    let expected_key = compute_pubkey_share(sorted_generation, &perpetrator_id);

    let actual_key_point = Setup::Point::from_bytes(&key.to_bytes())
        .map_err(|_| VerificationErrors::SlashableError("Invalid point".to_string()))?;

    if expected_key != actual_key_point {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Computed key {} does not match expected key {}",
            expected_key, key
        ))));
    }
    Ok(())
}

fn verify_partial_signature<Setup>(
    bad_partial: &BadPartialShare<Setup>,
    key: &Setup::DkgPubkey,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let sig =
        Setup::DkgSignature::from_bytes_safe(&bad_partial.data.message_signature).map_err(|e| {
            Box::new(VerificationErrors::SlashableError(format!(
                "While uncompressing data.bad_partial.data.message_signature {}",
                e
            ))) as Box<dyn std::error::Error>
        })?;

    if !key.verify_signature(bad_partial.data.message_cleartext.as_bytes(), &sig) {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Invalid partial signature {} from key {}",
            sig, key
        ))));
    }
    Ok(())
}

fn get_perpetrator_key<Setup>(
    bad_partial: &BadPartialShare<Setup>,
) -> Result<Setup::DkgPubkey, Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    Setup::DkgPubkey::from_bytes_safe(&bad_partial.data.partial_pubkey).map_err(|e| {
        Box::new(VerificationErrors::SlashableError(format!(
            "While uncompressing data.bad_partial.data.partial_pubkey {}",
            e
        ))) as Box<dyn std::error::Error>
    })
}

pub fn prove_wrong_final_key_generation<Setup>(
    data: &BadPartialShareData<Setup>,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    #[cfg(feature = "auth_commitment")]
    {
        verify_commitment_signature(data)?;
    }
    verify_generation_base_hashes(data)?;

    let mut sorted_generation = data.generations.to_vec();
    sorted_generation.sort_by(|a, b| a.base_hash.cmp(&b.base_hash));

    let perpetrator_index =
        find_perpetrator_index(&data.bad_partial.data.base_hash, &sorted_generation)?;

    let key = get_perpetrator_key(&data.bad_partial)?;

    verify_partial_signature(&data.bad_partial, &key)?;
    verify_expected_key::<Setup>(&sorted_generation, perpetrator_index, &key)?;

    Ok(())
}

#[cfg(feature = "auth_commitment")]
fn verify_commitment_signature<Setup>(
    data: &BadPartialShareData<Setup>,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let computed_hash = compute_partial_share_hash(&data.settings, &data.bad_partial);
    if computed_hash != data.bad_partial.commitment.hash.as_ref() {
        return Err(Box::new(VerificationErrors::UnslashableError(format!(
            "Invalid commitment hash expect {}, got {}",
            data.bad_partial.commitment.hash,
            hex::encode(&computed_hash)
        ))));
    }
    let key = Setup::CommitmentPubkey::from_bytes(&data.bad_partial.commitment.pubkey)
        .expect("Invalid pubkey");
    let sig = Setup::CommitmentSignature::from_bytes(&data.bad_partial.commitment.signature)
        .expect("Invalid signature");

    // Verify that the commitment made by the participant has the correct hash and signature
    if !key.verify_signature(data.bad_partial.commitment.hash.as_ref(), &sig) {
        return Err(Box::new(VerificationErrors::UnslashableError(format!(
            "Invalid commitment signature {} and key {}",
            sig, key
        ))));
    }
    Ok(())
}

fn find_perpetrator_index<Setup>(
    perpetrador_hash: &SHA256Raw,
    sorted_generation: &[BadPartialShareGeneration<Setup>],
) -> Result<usize, Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let mut perpetrator_index = None;
    for (i, generation) in sorted_generation.iter().enumerate() {
        if generation.base_hash == *perpetrador_hash {
            perpetrator_index = Some(i);
        }
    }
    let perpetrator_index = match perpetrator_index {
        Some(i) => i,
        None => {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Could not find perpetrator generation {}",
                perpetrador_hash
            ))));
        }
    };
    Ok(perpetrator_index)
}

fn compute_pubkey_share<Setup>(
    sorted: &[BadPartialShareGeneration<Setup>],
    perpetrator_id: &Setup::Scalar,
) -> Setup::Point
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let verification_vectors = deserialize_bad_partial_share_verification_vectors::<Setup>(sorted);

    let computed_keys_coeffs = agg_coefficients::<Setup::Curve>(&verification_vectors);
    let expected_key = evaluate_polynomial::<Setup::Curve>(&computed_keys_coeffs, perpetrator_id);
    Setup::Point::from_bytes(&expected_key.to_bytes()).expect("Invalid pubkey")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::*;

    #[test]
    fn test_get_index_in_commitments() {
        let mut hashes = vec![
            SHA256Raw::from([1u8; 32]),
            SHA256Raw::from([2u8; 32]),
            SHA256Raw::from([0u8; 32]),
        ];
        let dst = SHA256Raw::from([2u8; 32]);
        let index = get_index_in_commitments(&hashes, &dst).unwrap();
        assert_eq!(index, 2);
        hashes.sort();
        assert_eq!(hashes[index as usize], dst);
    }

    #[test]
    fn test_initial_commitment_hash_roundtrip() {
        type Setup = BlsDkgWithSecp256kCommitment;

        let settings = GenerateSettings {
            n: 2,
            k: 1,
            gen_id: DkgGenId::from([1u8; 16]),
        };

        let pk = <Setup as DkgSetupTypes<Setup>>::Point::identity().to_bytes();
        let base_pubkeys = vec![pk.clone(), pk];

        let hash = compute_initial_commitment_hash::<Setup>(&settings, &base_pubkeys);
        let commitment = InitialCommitment::<Setup> {
            hash,
            settings: settings.clone(),
            base_pubkeys: base_pubkeys.clone(),
        };

        assert!(verify_initial_commitment_hash::<Setup>(&commitment));

        let mut bad = commitment.clone();
        bad.base_pubkeys[0].as_mut()[0] ^= 1;
        assert!(!verify_initial_commitment_hash::<Setup>(&bad));
    }

    #[test]
    fn test_get_index_in_commitments_not_found() {
        let hashes = vec![
            SHA256Raw::from([1u8; 32]),
            SHA256Raw::from([2u8; 32]),
            SHA256Raw::from([3u8; 32]),
        ];
        let dst = SHA256Raw::from([9u8; 32]);
        assert!(get_index_in_commitments(&hashes, &dst).is_err());
    }

    fn dummy_generation(msg: &str) -> Generation<BlsDkgWithSecp256kCommitment> {
        Generation {
            verification_vector: vec![<BlsDkgWithSecp256kCommitment as DkgSetupTypes<
                BlsDkgWithSecp256kCommitment,
            >>::Point::identity()
            .to_bytes()],
            base_hash: SHA256Raw::from([0u8; 32]),
            partial_pubkey: <BlsDkgWithSecp256kCommitment as DkgSetupTypes<
                BlsDkgWithSecp256kCommitment,
            >>::Point::identity()
            .to_bytes(),
            message_cleartext: msg.to_string(),
            message_signature: BLSSignatureRaw([0u8; BLS_SIGNATURE_SIZE]),
        }
    }

    #[test]
    fn test_verify_generation_hashes_empty() {
        type Setup = BlsDkgWithSecp256kCommitment;
        let settings = GenerateSettings {
            n: 1,
            k: 1,
            gen_id: DkgGenId::from([0u8; 16]),
        };
        assert!(verify_generation_hashes::<Setup>(&[], &settings).is_err());
    }

    #[test]
    fn test_verify_generation_hashes_message_mismatch() {
        type Setup = BlsDkgWithSecp256kCommitment;
        let settings = GenerateSettings {
            n: 2,
            k: 1,
            gen_id: DkgGenId::from([0u8; 16]),
        };
        let g1 = dummy_generation("hello");
        let mut g2 = dummy_generation("hello");
        g2.message_cleartext = "world".to_string();
        let gens = vec![g1, g2];
        assert!(verify_generation_hashes::<Setup>(&gens, &settings).is_err());
    }

    #[test]
    fn test_verify_generations_wrong_n() {
        type Setup = BlsDkgWithSecp256kCommitment;
        let settings = GenerateSettings {
            n: 2,
            k: 1,
            gen_id: DkgGenId::from([0u8; 16]),
        };
        let g = dummy_generation("hello");
        let agg_key = <Setup as DkgSetupTypes<Setup>>::DkgPubkey::from_bytes(
            &<Setup as DkgSetupTypes<Setup>>::Point::identity().to_bytes(),
        )
        .unwrap();
        assert!(verify_generations::<Setup>(&[g], &settings, &agg_key).is_err());
    }
}
