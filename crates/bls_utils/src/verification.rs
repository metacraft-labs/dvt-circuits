use bls12_381::{G1Affine, G1Projective, G2Affine, Scalar};

use dvt_abi::{self};
use group::GroupEncoding;
use sha2::{Digest, Sha256};
use sp1_zkvm;

use crate::bls::{
    bls_id_from_u32, bls_verify, bls_verify_precomputed_hash, evaluate_polynomial, evaluate_polynomial_g1_projection, hash_message_to_g2, lagrange_interpolation, PublicKey, SecretKey
};

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

    let sk = SecretKey::from_bytes(&shared_secret.secret).unwrap();

    hasher.update(&seed_exchange.initial_commitment_hash);
    hasher.update(&sk.to_bytes());
    hasher.update(&shared_secret.dst_base_hash);
    hasher.update(&shared_secret.src_id);
    hasher.update(&shared_secret.dst_id);

    hasher.finalize().to_vec().try_into().unwrap()
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

pub fn to_g1_affine(pubkey: &dvt_abi::BLSPubkey) -> G1Affine {
    G1Affine::from_compressed(&pubkey).into_option().unwrap()
}

pub fn to_g1_projection(pubkey: &dvt_abi::BLSPubkey) -> G1Projective {
    G1Projective::from(to_g1_affine(pubkey))
}


pub fn verify_seed_exchange_commitment(
    verification_hashes: &dvt_abi::AbiVerificationHashes,
    seed_exchange: &dvt_abi::AbiSeedExchangeCommitment,
    initial_commitment: &dvt_abi::AbiInitialCommitment,
) -> Result<(), Box<dyn std::error::Error>> {
    let commitment = &seed_exchange.commitment;
    let shared_secret = &seed_exchange.shared_secret;

    let g1_pubkey = to_g1_affine(&commitment.pubkey);


    let g2_sig = &G2Affine::from_compressed(&commitment.signature)
    .into_option();
    if g2_sig.is_none() {
        return Err(Box::new(VerificationErrors::UnslashableError(
            String::from(format!(
                "Invalid field seeds_exchange_commitment.commitment.signature {}\n", 
                hex::encode(commitment.signature)
            ))
        )))
    }
    if !bls_verify_precomputed_hash(
        &g1_pubkey,
        &g2_sig.unwrap(),
        &G2Affine::from(&hash_message_to_g2(&commitment.hash)),
    ) {
        // Return unslashable error
        return Err(Box::new(VerificationErrors::UnslashableError(
            String::from(format!(
                "Invalid field seeds_exchange_commitment.commitment.signature {}\n",
                hex::encode(commitment.signature)
            )),
        )));
    }

    let sk = SecretKey::from_bytes(&shared_secret.secret);
    if sk.is_err() {
        return Err(Box::new(VerificationErrors::SlashableError(String::from(
            
            format!(
                "Invalid field seeds_exchange_commitment.shared_secret.secret: {} \n",
                sk.unwrap_err()
            ),
        ))));
    }

    let sk = sk.unwrap();

    let computed_commitment_hash = compute_seed_exchange_hash(seed_exchange);

    if computed_commitment_hash.to_vec() != seed_exchange.commitment.hash {
        return Err(Box::new(VerificationErrors::SlashableError(
            String::from(format!(
                "Invalid field seeds_exchange_commitment.commitment.hash. Expected: {:?}, got hash: {:?}\n",
                hex::encode(seed_exchange.commitment.hash),
                hex::encode(computed_commitment_hash.to_vec())
            )),
        )));
    }

    let dest_id = get_index_in_commitments(
        verification_hashes,
        &seed_exchange.shared_secret.dst_base_hash,
    );

    if dest_id.is_err() {
        return Err(Box::new(VerificationErrors::SlashableError(String::from(
            format!(
                "Invalid field seeds_exchange_commitment.shared_secret.dst_id: {} \n",
                dest_id.unwrap_err()
            ),
        ))));
    }

    let unwraped = dest_id.unwrap() + 1;
    let test_id = bls_id_from_u32(unwraped);

    let mut cfst: Vec<G1Affine> = Vec::new();
    for pubkey in &initial_commitment.verification_vector.pubkeys {
        cfst.push(to_g1_affine(pubkey));
    }

    let le_bytes = seed_exchange.shared_secret.dst_id.clone();

    let id = Scalar::from_bytes(&le_bytes).unwrap();

    if id != test_id {
        return Err(Box::new(VerificationErrors::SlashableError(String::from(
            "Invalid field seeds_exchange_commitment.shared_secret.dst_id\n",
        ))));
    }
    let eval_result = evaluate_polynomial(cfst, id);

    if !sk.to_public_key().eq(&eval_result) {
        return Err(Box::new(VerificationErrors::SlashableError(String::from(
            format!(
                "Bad secret field : Expected secret with public key: {:?}, got public key: {:?}\n",
                PublicKey::from_g1(&eval_result),
                sk.to_public_key()
            ),
        ))));
    }

    Ok(())
}

pub fn verify_initial_commitment_hash(commitment: &dvt_abi::AbiInitialCommitment) -> bool {
    let mut hasher = Sha256::new();

    hasher.update([commitment.settings.n]);
    hasher.update([commitment.settings.k]);
    hasher.update(commitment.settings.gen_id);
    for pubkey in &commitment.verification_vector.pubkeys {
        hasher.update(&pubkey);
    }
    let computed_hash = hasher.finalize().to_vec();
    computed_hash == commitment.hash
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
        verification_vector: dvt_abi::AbiVerificationVector {
            pubkeys: generation.verification_vector.clone(),
        },
    }
}

fn agg_final_keys(
    verification_vectors: &Vec<dvt_abi::AbiVerificationVector>,
    ids: &Vec<Scalar>,
) -> Vec<G1Affine> {
    let verification_vectors: Vec<Vec<G1Projective>> = verification_vectors
        .iter()
        .map(|vector| -> Vec<G1Projective> {
            vector
                .pubkeys
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
    verification_vectors: &Vec<dvt_abi::AbiVerificationVector>,
    ids: &Vec<Scalar>,
) -> Result<G1Affine, Box<dyn std::error::Error>> {
    let final_keys = agg_final_keys(&verification_vectors, &ids);
    let agg_key = lagrange_interpolation(&final_keys, &ids)?;
    return Ok(agg_key);
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
        // opcode count for n=5 924_860_863
        let ok = bls_verify_precomputed_hash(
            &to_g1_affine(&generation.partial_pubkey),
            &G2Affine::from_compressed(&generation.message_signature).into_option().unwrap(),
            &hashed_msg,
        );

        if !ok {
            return Err(Box::new(VerificationErrors::UnslashableError(
                String::from(format!(
                    "Invalid signature {}",
                    hex::encode(generation.message_signature)
                )),
            )));
        }

        let initial_commitment = generate_initial_commitment(generation, &settings);
        let ok = verify_initial_commitment_hash(&initial_commitment);
        if !ok {
            return Err(Box::new(VerificationErrors::UnslashableError(
                String::from(format!(
                    "Invalid initial commitment hash {}",
                    hex::encode(initial_commitment.hash)
                )),
            )));
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

    let verification_vectors: Vec<dvt_abi::AbiVerificationVector> = sorted
        .iter()
        .map(|generation| -> dvt_abi::AbiVerificationVector {
            dvt_abi::AbiVerificationVector {
                pubkeys: generation.verification_vector.clone(),
            }
        })
        .collect();

    let ids: Vec<Scalar> = sorted
        .iter()
        .enumerate()
        .map(|(i, _)| -> Scalar { bls_id_from_u32((i + 1) as u32) })
        .collect();

    let computed_key = compute_agg_key_from_dvt(&verification_vectors, &ids)?;

    let agg_key = G1Affine::from_compressed(agg_key).into_option();

    if agg_key.is_none() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid aggregate public key",
        )));
    }

    let agg_key = agg_key.unwrap();
    if computed_key != agg_key {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Computed key {} does not match aggregate public key {}",
                hex::encode(computed_key.to_compressed()),
                hex::encode(agg_key.to_compressed())
            ),
        )));
    }

    let partial_keys: Vec<G1Affine> = sorted
        .iter()
        .map(|generation| -> G1Affine {
            G1Affine::from_compressed(&generation.partial_pubkey)
                .into_option()
                .unwrap()
        })
        .collect();

     let computed_key = lagrange_interpolation(&partial_keys, &ids)?;

    if computed_key != agg_key {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Computed key {} does not match aggregate public key {}",
                hex::encode(computed_key.to_compressed()),
                hex::encode(agg_key.to_compressed())
            ),
        )));
    }

    Ok(())
}

pub fn prove_wrong_final_key_generation(
    data: &dvt_abi::AbiWrongFinalKeyGeneration,
) -> Result<(), Box<dyn std::error::Error>> {
    verify_generation_hashes(&data.generations, &data.settings)?;

    let mut sorted = data.generations.to_vec();
    sorted.sort_by(|a, b| a.base_hash.cmp(&b.base_hash));

    let mut perpetrator_index = None;
    for i in 0..sorted.len() {
        if sorted[i].base_hash == data.perpatrator_hash {
            perpetrator_index = Some(i);
        }
    }

    if perpetrator_index.is_none() {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Perpetrator not found",
        )));
    }

    let perpetrator_index = perpetrator_index.unwrap();

    let perpetrator_bls_id = bls_id_from_u32((perpetrator_index + 1) as u32);

    let verification_vectors = sorted
        .iter()
        .map(|generation| -> dvt_abi::AbiVerificationVector {
            dvt_abi::AbiVerificationVector {
                pubkeys: generation.verification_vector.clone(),
            }
        })
        .collect();

    let ids = sorted
        .iter()
        .enumerate()
        .map(|(i, _)| -> Scalar { bls_id_from_u32((i + 1) as u32) })
        .collect();

    let computed_key = agg_final_keys(&verification_vectors, &ids);

    let expected_key = evaluate_polynomial(computed_key, perpetrator_bls_id);

    if expected_key
        == G1Affine::from_compressed(&sorted[perpetrator_index].partial_pubkey)
            .into_option()
            .unwrap()
    {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Computed key {} does not match expected key {}",
                hex::encode(expected_key.to_compressed()),
                hex::encode(
                    G1Affine::from_compressed(&sorted[perpetrator_index].partial_pubkey)
                        .into_option()
                        .unwrap()
                        .to_compressed()
                )
            ),
        )));
    }

    Ok(())
}
