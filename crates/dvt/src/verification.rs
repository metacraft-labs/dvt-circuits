use crate::crypto::{BlsSecretKey, ByteConvertible, CryptoKeys, PublicKey, SecretKey};
use crate::types::*;
use sha2::{Digest, Sha256};

use crate::dvt_math::{
    agg_coefficients, evaluate_polynomial, lagrange_interpolation, BlsG1, BlsG1Curve, BlsScalar,
    Curve, TScalar,
};

use crate::crypto::to_g1_affine;

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

pub fn compute_seed_exchange_hash(seed_exchange: &SeedExchangeCommitment) -> SHA256Raw {
    let shared_secret = &seed_exchange.shared_secret;
    let mut hasher = Sha256::new();

    let sk = BlsSecretKey::from_bytes(&shared_secret.secret).expect("Invalid secret key");

    hasher.update(seed_exchange.initial_commitment_hash.as_ref());
    hasher.update(sk.to_bytes().as_ref());
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

pub fn verify_seed_exchange_commitment(
    verification_hashes: &VerificationHashes,
    seed_exchange: &SeedExchangeCommitment,
    initial_commitment: &InitialCommitment<BlsG1Curve>,
) -> Result<(), Box<dyn std::error::Error>> {
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

    let sk = match BlsSecretKey::from_bytes(&shared_secret.secret) {
        Ok(sk) => sk,
        Err(e) => {
            return Err(Box::new(VerificationErrors::SlashableError(format!(
                "Invalid field seeds_exchange_commitment.shared_secret.secret: {e} \n"
            ))));
        }
    };

    let computed_commitment_hash = compute_seed_exchange_hash(seed_exchange);

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
    let id = BlsScalar::from_u32(dest_id);

    let cfst: Vec<BlsG1> = initial_commitment
        .base_pubkeys
        .iter()
        .map(BlsG1::from_bytes)
        .map(|x| x.expect("Invalid pubkey"))
        .collect();

    let eval_result = evaluate_polynomial::<BlsG1Curve>(&cfst, &id);
    let eval_result = eval_result.g1;

    if !sk.to_public_key().equal(&eval_result) {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Bad secret field : Expected secret with public key: {:?}, got public key: {:?}\n",
            hex::encode(eval_result.to_compressed()),
            sk.to_public_key()
        ))));
    }

    Ok(())
}

pub fn compute_initial_commitment_hash<Setup>(
    commitment: &InitialCommitment<Setup::Curve>,
) -> SHA256Raw
where
    Setup: DvtSetup + DvtSetupTypes<Setup>,
{
    let mut hasher = Sha256::new();

    hasher.update(commitment.settings.gen_id.as_ref());
    hasher.update([commitment.settings.n]);
    hasher.update([commitment.settings.k]);

    let len = commitment.base_pubkeys.len() as u8;
    hasher.update([len]);

    for pubkey in &commitment.base_pubkeys {
        hasher.update(pubkey.as_arr());
    }
    hasher
        .finalize()
        .to_vec()
        .try_into()
        .expect("Vec must be exactly 32 bytes")
}

pub fn verify_initial_commitment_hash<Setup>(commitment: &InitialCommitment<Setup::Curve>) -> bool
where
    Setup: DvtSetup + DvtSetupTypes<Setup>,
{
    compute_initial_commitment_hash::<Setup>(commitment) == commitment.hash
}

fn generate_initial_commitment<Setup>(
    generation: &Generation<Setup>,
    settings: &GenerateSettings,
) -> InitialCommitment<Setup::Curve>
where
    Setup: DvtSetup + DvtSetupTypes<Setup>,
{
    InitialCommitment::<Setup::Curve> {
        hash: generation.base_hash,
        settings: GenerateSettings {
            n: settings.n,
            k: settings.k,
            gen_id: settings.gen_id,
        },
        base_pubkeys: generation.verification_vector.clone(),
    }
}

fn compute_agg_key_from_dvt<C: Curve>(
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
    Setup: DvtSetup + DvtSetupTypes<Setup>,
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

    let message_mapping =
        Setup::GenCrypto::precompute_message_mapping(generations[0].message_cleartext.as_bytes());

    for generation in generations.iter() {
        let signature = Setup::DvtSignature::from_bytes(&generation.message_signature)
            .expect("Invalid signature");
        let key =
            Setup::DvtPubkey::from_bytes(&generation.partial_pubkey).expect("Invalid public key");

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

pub fn verify_generations(
    generations: &[Generation<BlsDvtWithBlsCommitment>],
    settings: &GenerateSettings,
    agg_key: &BLSPubkeyRaw,
) -> Result<(), Box<dyn std::error::Error>> {
    if generations.len() != settings.n as usize {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid number of generations",
        )));
    }

    verify_generation_hashes(generations, settings)?;

    let mut sorted = generations.to_vec();
    sorted.sort_by(|a, b| a.base_hash.cmp(&b.base_hash));

    let verification_vectors: Vec<Vec<BlsG1>> = sorted
        .iter()
        .map(|generation| -> Vec<BlsG1> {
            generation
                .verification_vector
                .iter()
                .map(|pt| BlsG1 {
                    g1: to_g1_affine(pt),
                })
                .collect()
        })
        .collect();

    let ids: Vec<BlsScalar> = sorted
        .iter()
        .enumerate()
        .map(|(i, _)| BlsScalar::from_u32((i + 1) as u32))
        .collect();

    let computed_key = compute_agg_key_from_dvt::<BlsG1Curve>(&verification_vectors, &ids)?;
    let agg_key = BlsG1::from_bytes(agg_key).expect("Invalid g1 point");

    if agg_key != computed_key {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Computed key {} does not match aggregate public key {}",
                computed_key, agg_key
            ),
        )));
    }

    let partial_keys: Vec<BlsG1> = sorted
        .iter()
        .map(|generation| BlsG1::from_bytes(&generation.partial_pubkey).expect("Invalid g1 point"))
        .collect();

    let computed_key = lagrange_interpolation::<BlsG1Curve>(&partial_keys, &ids)?;

    if computed_key != agg_key {
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
    Setup: DvtSetup + DvtSetupTypes<Setup>,
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

pub fn verify_commitment<Crypto: CryptoKeys>(commitment: &Commitment<Crypto>) -> bool {
    let key = Crypto::Pubkey::from_bytes_safe(&commitment.pubkey).unwrap();
    let signature = Crypto::Signature::from_bytes(&commitment.signature).unwrap();
    key.verify_signature(commitment.hash.as_ref(), &signature)
}

pub fn prove_wrong_final_key_generation<Setup>(
    data: &BadPartialShareData<Setup>,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DvtSetup + DvtSetupTypes<Setup>,
{
    verify_commitment_signature(data)?;
    // Verify that the generation base hashes are correct
    for generation in data.generations.iter() {
        let ok = verify_initial_commitment_hash::<Setup>(&InitialCommitment::<Setup::Curve> {
            hash: generation.base_hash,
            settings: data.settings.clone(),
            base_pubkeys: generation.verification_vector.clone(),
        });
        if !ok {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Invalid generation base hash {}",
                generation.base_hash
            ))));
        }
    }

    let mut sorted_generation = data.generations.to_vec();
    sorted_generation.sort_by(|a, b| a.base_hash.cmp(&b.base_hash));

    let perpetrator_index =
        find_perpetrator_index(&data.bad_partial.data.base_hash, &sorted_generation)?;

    let key = match Setup::DvtPubkey::from_bytes_safe(&data.bad_partial.data.partial_pubkey) {
        Ok(key) => key,
        Err(e) => {
            return Err(Box::new(VerificationErrors::SlashableError(format!(
                "While uncompressing data.bad_partial.data.partial_pubkey {}",
                e
            ))));
        }
    };

    let sig = match Setup::DvtSignature::from_bytes_safe(&data.bad_partial.data.message_signature) {
        Ok(sig) => sig,
        Err(e) => {
            return Err(Box::new(VerificationErrors::SlashableError(format!(
                "While uncompressing data.bad_partial.data.message_signature {}",
                e
            ))));
        }
    };

    if !key.verify_signature(data.bad_partial.data.message_cleartext.as_bytes(), &sig) {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Invalid partial signature {} from key {}",
            sig, key
        ))));
    }

    let perpetrator_bls_id = Setup::Scalar::from_u32((perpetrator_index + 1) as u32);

    let expected_key = compute_pubkey_share(&sorted_generation, &perpetrator_bls_id);

    if expected_key != Setup::Point::from_bytes(&key.to_bytes()).expect("Invalid point") {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Computed key {} does not match expected key {}",
            expected_key, key,
        ))));
    }

    Ok(())
}

fn verify_commitment_signature<Setup>(
    data: &BadPartialShareData<Setup>,
) -> Result<(), Box<dyn std::error::Error>>
where
    Setup: DvtSetup + DvtSetupTypes<Setup>,
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
    Setup: DvtSetup + DvtSetupTypes<Setup>,
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
    perpetrator_bls_id: &Setup::Scalar,
) -> Setup::Point
where
    Setup: DvtSetup + DvtSetupTypes<Setup>,
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
    let expected_key = evaluate_polynomial::<Setup::Curve>(&computed_keys, perpetrator_bls_id);
    Setup::Point::from_bytes(&expected_key.to_bytes()).expect("Invalid pubkey")
}
