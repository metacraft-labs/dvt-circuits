use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};

use dvt_abi::{self, BLSPubkey, SHA256};
use sha2::{Digest, Sha256};

use crate::dvt_math::{
    evaluate_polynomial, evaluate_polynomial_g1_projection, lagrange_interpolation,
};

use crate::bls_common::{bls_id_from_u32, hash_message_to_g2, to_g1_affine, to_g1_projection};

use crate::bls_keys::*;

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

pub fn compute_seed_exchange_hash(
    seed_exchange: &dvt_abi::AbiSeedExchangeCommitment,
) -> dvt_abi::SHA256 {
    let shared_secret = &seed_exchange.shared_secret;
    let mut hasher = Sha256::new();

    let sk = SecretKey::from_bytes(&shared_secret.secret).expect("Invalid secret key");

    hasher.update(&seed_exchange.initial_commitment_hash);
    hasher.update(&sk.to_bytes());
    hasher.update(&shared_secret.dst_base_hash);

    hasher
        .finalize()
        .to_vec()
        .try_into()
        .expect("Can't produce SHA256")
}

pub fn get_index_in_commitments(
    commitments: &dvt_abi::AbiVerificationHashes,
    destination_id: &dvt_abi::SHA256,
) -> Result<u32, Box<dyn std::error::Error>> {
    let mut sorted = commitments.clone();
    sorted.sort();
    for i in 0..sorted.len() {
        if commitments[i] == *destination_id {
            return Ok(i as u32);
        }
    }

    Err(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "Could not find destination in commitments",
    )))
}

pub fn verify_seed_exchange_commitment(
    verification_hashes: &dvt_abi::AbiVerificationHashes,
    seed_exchange: &dvt_abi::AbiSeedExchangeCommitment,
    initial_commitment: &dvt_abi::AbiInitialCommitment,
) -> Result<(), Box<dyn std::error::Error>> {
    let commitment = &seed_exchange.commitment;
    let shared_secret = &seed_exchange.shared_secret;

    let pubkey = PublicKey::from_bytes_safe(&commitment.pubkey)?;

    let signature = Signature::from_bytes(&commitment.signature)?;

    if !pubkey.verify_signature(&commitment.hash, &signature) {
        return Err(Box::new(VerificationErrors::UnslashableError(format!(
            "Invalid field seeds_exchange_commitment.commitment.signature {},
            message: {}
            pubkey: {},
            \n",
            hex::encode(&commitment.signature),
            hex::encode(&commitment.hash),
            hex::encode(&commitment.pubkey)
        ))));
    }

    let sk = match SecretKey::from_bytes(&shared_secret.secret) {
        Ok(sk) => sk,
        Err(e) => {
            return Err(Box::new(VerificationErrors::SlashableError(format!(
                "Invalid field seeds_exchange_commitment.shared_secret.secret: {e} \n"
            ))));
        }
    };

    let computed_commitment_hash = compute_seed_exchange_hash(seed_exchange);

    if computed_commitment_hash.to_vec() != seed_exchange.commitment.hash {
        return Err(Box::new(VerificationErrors::SlashableError(
            format!(
                "Invalid field seeds_exchange_commitment.commitment.hash. Expected: {:?}, got hash: {:?}\n",
                hex::encode(seed_exchange.commitment.hash),
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
    let id = bls_id_from_u32(dest_id);

    let cfst = initial_commitment
        .base_pubkeys
        .iter()
        .into_iter()
        .map(to_g1_affine)
        .collect();

    let eval_result = evaluate_polynomial(cfst, id);

    if !sk.to_public_key().eq(&eval_result) {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Bad secret field : Expected secret with public key: {:?}, got public key: {:?}\n",
            hex::encode(eval_result.to_compressed()),
            sk.to_public_key()
        ))));
    }

    Ok(())
}

pub fn compute_initial_commitment_hash(commitment: &dvt_abi::AbiInitialCommitment) -> SHA256 {
    let mut hasher = Sha256::new();

    hasher.update(commitment.settings.gen_id);
    hasher.update([commitment.settings.n]);
    hasher.update([commitment.settings.k]);

    let len = commitment.base_pubkeys.len() as u8;
    hasher.update([len]);

    for pubkey in &commitment.base_pubkeys {
        hasher.update(&pubkey);
    }
    hasher
        .finalize()
        .to_vec()
        .try_into()
        .expect("Vec must be exactly 32 bytes")
}

pub fn verify_initial_commitment_hash(commitment: &dvt_abi::AbiInitialCommitment) -> bool {
    print!(
        "commitment.hash: {:?}, calced: {:?}\n",
        hex::encode(commitment.hash),
        hex::encode(compute_initial_commitment_hash(commitment))
    );
    compute_initial_commitment_hash(commitment) == commitment.hash
}

fn generate_initial_commitment(
    generation: &dvt_abi::AbiGeneration,
    settings: &dvt_abi::AbiGenerateSettings,
) -> dvt_abi::AbiInitialCommitment {
    dvt_abi::AbiInitialCommitment {
        hash: generation.base_hash,
        settings: dvt_abi::AbiGenerateSettings {
            n: settings.n,
            k: settings.k,
            gen_id: settings.gen_id,
        },
        base_pubkeys: generation.verification_vector.clone(),
    }
}

fn agg_coefficients(
    verification_vectors: &Vec<Vec<BLSPubkey>>,
    ids: &Vec<Scalar>,
) -> Vec<G1Affine> {
    let verification_vectors: Vec<Vec<G1Projective>> = verification_vectors
        .iter()
        .map(|vector| -> Vec<G1Projective> {
            vector
                .iter()
                .map(|pk: &[u8; 48]| to_g1_projection(&pk))
                .collect()
        })
        .collect();

    let mut final_cfs = Vec::new();
    for i in 0..verification_vectors[0].len() {
        let mut sum = G1Projective::identity();
        for j in 0..verification_vectors.len() {
            sum = sum + verification_vectors[j][i];
        }
        final_cfs.push(sum);
    }
    let mut final_keys = Vec::new();
    for i in 0..ids.len() {
        let tmp = evaluate_polynomial_g1_projection(&final_cfs, ids[i]);
        final_keys.push(tmp);
    }
    final_keys.iter().map(|x| G1Affine::from(x)).collect()
}

fn compute_agg_key_from_dvt(
    verification_vectors: &Vec<Vec<BLSPubkey>>,
    ids: &Vec<Scalar>,
) -> Result<PublicKey, Box<dyn std::error::Error>> {
    let coefficients = agg_coefficients(&verification_vectors, &ids);
    let agg_key = lagrange_interpolation(&coefficients, &ids)?;
    return Ok(PublicKey::from_g1(&agg_key));
}

pub fn verify_generation_hashes(
    generations: &[dvt_abi::AbiGeneration],
    settings: &dvt_abi::AbiGenerateSettings,
) -> Result<(), Box<dyn std::error::Error>> {
    if generations.len() == 0 {
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

    let hashed_msg = G2Affine::from(&hash_message_to_g2(&generations[0].message_cleartext));

    for (_, generation) in generations.iter().enumerate() {
        let signature = Signature::from_bytes(&generation.message_signature)?;
        let key = PublicKey::from_bytes(&generation.partial_pubkey)?;
        if !key.verify_signature_precomputed_hash(&hashed_msg, &signature) {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Invalid signature {}",
                hex::encode(generation.message_signature)
            ))));
        }

        let initial_commitment = generate_initial_commitment(generation, &settings);
        let ok = verify_initial_commitment_hash(&initial_commitment);
        if !ok {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Invalid initial commitment hash {}",
                hex::encode(initial_commitment.hash)
            ))));
        }
    }
    Ok(())
}

pub fn verify_generations(
    generations: &[dvt_abi::AbiGeneration],
    settings: &dvt_abi::AbiGenerateSettings,
    agg_key: &dvt_abi::BLSPubkey,
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

    let verification_vectors: Vec<Vec<BLSPubkey>> = sorted
        .iter()
        .map(|generation| -> Vec<BLSPubkey> { generation.verification_vector.clone() })
        .collect();

    let ids: Vec<Scalar> = sorted
        .iter()
        .enumerate()
        .map(|(i, _)| -> Scalar { bls_id_from_u32((i + 1) as u32) })
        .collect();

    let computed_key = compute_agg_key_from_dvt(&verification_vectors, &ids)?;
    let agg_key = PublicKey::from_bytes(agg_key)?;

    if computed_key != agg_key {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Computed key {} does not match aggregate public key {}",
                computed_key, agg_key
            ),
        )));
    }

    let partial_keys: Vec<G1Affine> = sorted
        .iter()
        .map(|generation| -> G1Affine {
            G1Affine::from_compressed(&generation.partial_pubkey)
                .into_option()
                .expect("Invalid public key")
        })
        .collect();

    let computed_key = PublicKey::from_g1(&lagrange_interpolation(&partial_keys, &ids)?);

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

pub fn compute_partial_share_hash(
    settings: &dvt_abi::AbiGenerateSettings,
    partial_share: &dvt_abi::AbiBadPartialShare,
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&settings.gen_id);
    hasher.update(&[settings.n]);
    hasher.update(&[settings.k]);

    let len = partial_share.data.verification_vector.len() as u8;
    hasher.update([len]);

    for pubkey in &partial_share.data.verification_vector {
        hasher.update(&pubkey);
    }

    hasher.update(&partial_share.data.base_hash);
    hasher.update(&partial_share.data.partial_pubkey);

    let len = partial_share.data.message_cleartext.len() as u8;
    hasher.update([len]);
    hasher.update(&partial_share.data.message_cleartext);
    hasher.update(&partial_share.data.message_signature);

    hasher.finalize().to_vec()
}

pub fn prove_wrong_final_key_generation(
    data: &dvt_abi::AbiBadPartialShareData,
) -> Result<(), Box<dyn std::error::Error>> {
    verify_commitment_signature(data)?;
    // Verify that the generation base hashes are correct
    for (_, generation) in data.generations.iter().enumerate() {
        let ok = verify_initial_commitment_hash(&dvt_abi::AbiInitialCommitment {
            hash: generation.base_hash,
            settings: data.settings.clone(),
            base_pubkeys: generation.verification_vector.clone(),
        });
        if !ok {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Invalid generation base hash {}",
                hex::encode(&generation.base_hash)
            ))));
        }
    }

    let mut sorted_generation = data.generations.to_vec();
    sorted_generation.sort_by(|a, b| a.base_hash.cmp(&b.base_hash));

    let perpetrator_index =
        find_perpetrator_index(&data.bad_partial.data.base_hash, &sorted_generation)?;

    let key = match PublicKey::from_bytes_safe(&data.bad_partial.data.partial_pubkey) {
        Ok(key) => key,
        Err(e) => {
            return Err(Box::new(VerificationErrors::SlashableError(format!(
                "While uncompressing data.bad_partial.data.partial_pubkey {}",
                e.to_string()
            ))));
        }
    };

    let sig = match Signature::from_bytes_safe(&data.bad_partial.data.message_signature) {
        Ok(sig) => sig,
        Err(e) => {
            return Err(Box::new(VerificationErrors::SlashableError(format!(
                "While uncompressing data.bad_partial.data.message_signature {}",
                e.to_string()
            ))));
        }
    };
    if !key.verify_signature(&data.bad_partial.data.message_cleartext, &sig) {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Invalid partial signature {} from key {}",
            sig, key
        ))));
    }

    let perpetrator_bls_id = bls_id_from_u32((perpetrator_index + 1) as u32);

    let expected_key = compute_pubkey_share(sorted_generation, perpetrator_bls_id);

    if expected_key != key {
        return Err(Box::new(VerificationErrors::SlashableError(format!(
            "Computed key {} does not match expected key {}",
            expected_key, key,
        ))));
    }

    Ok(())
}

fn verify_commitment_signature(
    data: &dvt_abi::AbiBadPartialShareData,
) -> Result<(), Box<dyn std::error::Error>> {
    let computed_hash = compute_partial_share_hash(&data.settings, &data.bad_partial);
    if computed_hash != data.bad_partial.commitment.hash {
        return Err(Box::new(VerificationErrors::UnslashableError(format!(
            "Invalid commitment hash expect {}, got {}",
            hex::encode(&data.bad_partial.commitment.hash),
            hex::encode(&computed_hash)
        ))));
    }
    let key = PublicKey::from_bytes(&data.bad_partial.commitment.pubkey)?;
    let sig = Signature::from_bytes(&data.bad_partial.commitment.signature)?;

    // Verify that the commitment made by the participant has the correct hash and signature
    if !key.verify_signature(&data.bad_partial.commitment.hash, &sig) {
        return Err(Box::new(VerificationErrors::UnslashableError(format!(
            "Invalid commitment signature {} and key {}",
            sig, key
        ))));
    }
    Ok(())
}

fn find_perpetrator_index(
    perpetrador_hash: &dvt_abi::SHA256,
    sorted_generation: &Vec<dvt_abi::AbiBadPartialShareGeneration>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut perpetrator_index = None;
    for i in 0..sorted_generation.len() {
        if sorted_generation[i].base_hash == *perpetrador_hash {
            perpetrator_index = Some(i);
        }
    }
    let perpetrator_index = match perpetrator_index {
        Some(i) => i,
        None => {
            return Err(Box::new(VerificationErrors::UnslashableError(format!(
                "Could not find perpetrator generation {}",
                hex::encode(perpetrador_hash)
            ))));
        }
    };
    Ok(perpetrator_index)
}

fn compute_pubkey_share(
    sorted: Vec<dvt_abi::AbiBadPartialShareGeneration>,
    perpetrator_bls_id: Scalar,
) -> PublicKey {
    let verification_vectors = sorted
        .iter()
        .map(|generation| -> Vec<BLSPubkey> { generation.verification_vector.clone() })
        .collect();

    let ids = sorted
        .iter()
        .enumerate()
        .map(|(i, _)| -> Scalar { bls_id_from_u32((i + 1) as u32) })
        .collect();

    let computed_keys = agg_coefficients(&verification_vectors, &ids);
    let expected_key = evaluate_polynomial(computed_keys, perpetrator_bls_id);
    PublicKey::from_g1(&expected_key)
}
