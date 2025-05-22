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

pub fn verify_seed_exchange_commitment<Setup>(
    verification_hashes: &VerificationHashes,
    seed_exchange: &SeedExchangeCommitment<Setup>,
    initial_commitment: &InitialCommitment<Setup>,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let commitment = &seed_exchange.commitment;

    let shared_secret = &seed_exchange.shared_secret;

    if !verify_commitment(&seed_exchange.commitment) {
        return Err(Box::new(VerificationErrors::UnslashableError(format!(
            "Invalid field seeds_exchange_commitment.commitment.signature {},
            message: {}
            pubkey: {},
            \n",
            commitment.signature, commitment.hash, commitment.pubkey
        ))));
    }

    let sk = match Setup::DkgSecretKey::from_bytes(&shared_secret.secret) {
        Ok(sk) => sk,
        Err(e) => {
            return Err(Box::new(VerificationErrors::SlashableError(format!(
                "Invalid field seeds_exchange_commitment.shared_secret.secret: {e} \n"
            ))));
        }
    };

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

    let dest_id = match get_index_in_commitments(
        verification_hashes,
        &seed_exchange.shared_secret.dst_base_hash,
    ) {
        Ok(id) => id,
        Err(e) => {
            return Err(Box::new(VerificationErrors::SlashableError(format!(
                "Invalid field seeds_exchange_commitment.shared_secret.dst_base_hash: {e} \n"
            ))));
        }
    };

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

pub fn compute_initial_commitment_hash<Setup>(
    settings: &GenerateSettings,
    base_pubkeys: &Vec<RawBytes<Setup::Point>>,
) -> SHA256Raw
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let mut hasher = Sha256::new();

    hasher.update(settings.gen_id.as_ref());
    hasher.update([settings.n]);
    hasher.update([settings.k]);

    let len = base_pubkeys.len() as u8;
    hasher.update([len]);

    for pubkey in base_pubkeys {
        hasher.update(pubkey.as_arr());
    }
    hasher
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

fn compute_agg_key_from_dkg<C: Curve>(
    verification_vectors: &[Vec<C::Point>],
    ids: &[C::Scalar],
) -> Result<C::Point, Box<dyn std::error::Error>> {
    let coefficients = agg_coefficients::<C>(verification_vectors, ids);
    lagrange_interpolation::<C>(&coefficients, ids)
}

pub fn verify_generation_hashes<Setup>(
    generations: &[Generation<Setup>],
    settings: &GenerateSettings,
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
        let ok = verify_initial_commitment_hash::<Setup>(&initial_commitment);
        if !ok {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Invalid initial commitment hash {}",
                initial_commitment.hash
            ))));
        }
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

    let mut sorted = generations.to_vec();
    sorted.sort_by(|a, b| a.base_hash.cmp(&b.base_hash));

    let verification_vectors: Vec<Vec<Setup::Point>> = sorted
        .iter()
        .map(|generation| -> Vec<Setup::Point> {
            generation
                .verification_vector
                .iter()
                .map(|pt| Setup::Point::from_bytes(pt).expect("Invalid point"))
                .collect()
        })
        .collect();

    let ids: Vec<Setup::Scalar> = sorted
        .iter()
        .enumerate()
        .map(|(i, _)| Setup::Scalar::from_u32((i + 1) as u32))
        .collect();

    let computed_key = compute_agg_key_from_dkg::<Setup::Curve>(&verification_vectors, &ids)?;

    if agg_key.to_bytes() != computed_key.to_bytes() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Computed key {} does not match aggregate public key {}",
                computed_key, agg_key
            ),
        )));
    }

    let partial_keys: Vec<Setup::Point> = sorted
        .iter()
        .map(|generation| {
            Setup::Point::from_bytes(&generation.partial_pubkey).expect("Invalid g1 point")
        })
        .collect();

    let computed_key = lagrange_interpolation::<Setup::Curve>(&partial_keys, &ids)?;

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

pub fn compute_partial_share_hash<Setup>(
    settings: &GenerateSettings,
    partial_share: &BadPartialShare<Setup>,
) -> Vec<u8>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    let mut hasher = Sha256::new();
    hasher.update(settings.gen_id.as_ref());
    hasher.update([settings.n]);
    hasher.update([settings.k]);

    let len = partial_share.data.verification_vector.len() as u8;
    hasher.update([len]);

    for pubkey in &partial_share.data.verification_vector {
        hasher.update(pubkey.as_arr());
    }

    hasher.update(partial_share.data.base_hash.as_ref());
    hasher.update(partial_share.data.partial_pubkey.as_arr());

    let len = partial_share.data.message_cleartext.len() as u8;
    hasher.update([len]);
    hasher.update(&partial_share.data.message_cleartext);
    hasher.update(partial_share.data.message_signature.as_arr());

    hasher.finalize().to_vec()
}

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

pub fn prove_wrong_final_key_generation<Setup>(
    data: &BadPartialShareData<Setup>,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup>,
{
    verify_commitment_signature(data)?;
    verify_generation_base_hashes(data)?;

    let mut sorted_generation = data.generations.to_vec();
    sorted_generation.sort_by(|a, b| a.base_hash.cmp(&b.base_hash));

    let perpetrator_index =
        find_perpetrator_index(&data.bad_partial.data.base_hash, &sorted_generation)?;

    let key =
        Setup::DkgPubkey::from_bytes_safe(&data.bad_partial.data.partial_pubkey).map_err(|e| {
            VerificationErrors::SlashableError(format!(
                "While uncompressing data.bad_partial.data.partial_pubkey {}",
                e
            ))
        })?;

    let sig = Setup::DkgSignature::from_bytes_safe(&data.bad_partial.data.message_signature)
        .map_err(|e| {
            VerificationErrors::SlashableError(format!(
                "While uncompressing data.bad_partial.data.message_signature {}",
                e
            ))
        })?;

    if !key.verify_signature(data.bad_partial.data.message_cleartext.as_bytes(), &sig) {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Invalid partial signature {} from key {}",
            sig, key
        ))));
    }

    verify_expected_key::<Setup>(&sorted_generation, perpetrator_index, &key)?;

    Ok(())
}

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
    let verification_vectors: Vec<Vec<Setup::Point>> = sorted
        .iter()
        .map(|generation| {
            generation
                .verification_vector
                .iter()
                .map(Setup::Point::from_bytes)
                .map(|x| x.expect("Invalid pubkey"))
                .collect()
        })
        .collect();

    let ids: Vec<Setup::Scalar> = sorted
        .iter()
        .enumerate()
        .map(|(i, _)| Setup::Scalar::from_u32((i + 1) as u32))
        .collect();

    let computed_keys = agg_coefficients::<Setup::Curve>(&verification_vectors, &ids);
    let expected_key = evaluate_polynomial::<Setup::Curve>(&computed_keys, perpetrator_id);
    Setup::Point::from_bytes(&expected_key.to_bytes()).expect("Invalid pubkey")
}
