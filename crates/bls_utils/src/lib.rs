use std::clone;

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve}, pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar   
};

use sha2::{Sha256, Digest};
use dvt_abi;
use sp1_zkvm;

pub fn evaluate_polynomial(cfs: Vec<G1Affine>, x: Scalar) -> G1Affine {
    let cfst: Vec<G1Projective> = cfs.iter().map(|c| G1Projective::from(c)).collect();
    let count = cfst.len();
    if count == 0 {
        return G1Affine::identity();
    } else if count == 1 {
        return cfs[0];
    } else {       
        let mut y = cfst[count - 1];
        for i in 2..(count+1) {
            y = y * x + cfs[count - i];
        }
        return G1Affine::from(y);
    }    
}


pub fn hash_message_to_g2(msg: &[u8], domain: &[u8]) -> G2Projective {
    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve([msg], domain)
}

pub fn bls_verify(
    pubkey: &G1Affine,
    signature: &G2Affine,
    message: &[u8]
) -> bool {

    let domain = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    let pk_projective = G1Projective::from(pubkey);
    let sig_projective = G2Projective::from(signature);

    let hashed_msg = hash_message_to_g2(message, domain);
    let left = pairing(&G1Affine::from(pk_projective), &G2Affine::from(hashed_msg));
    let right = pairing(&G1Affine::generator(), &G2Affine::from(sig_projective));

    left == right
}
pub enum ProveResult {
    Ok,
    SlashableError,
    UnslashableError,
}

pub fn verify_seed_exchange_commitment(seed_exchange: &dvt_abi::AbiSeedExchangeCommitment, initial_commitment: &dvt_abi::AbiInitialCommitment) -> ProveResult {
    let commitment = &seed_exchange.commitment;
    let shared_secret = &seed_exchange.shared_secret;

    if !bls_verify(
        &G1Affine::from_compressed(&commitment.pubkey).into_option().unwrap(),
        &G2Affine::from_compressed(&commitment.signature).into_option().unwrap(),
        &commitment.hash
    ) {
        return ProveResult::UnslashableError;
    }

    if SecretKey::from_bytes(&shared_secret.secret).is_err() {
        return ProveResult::SlashableError;
    }

    let mut hasher = Sha256::new();
    hasher.update(&seed_exchange.initial_commitment_hash);

    let sk = SecretKey::from_bytes(&shared_secret.secret).unwrap();
    hasher.update(&sk.key.to_bytes());
    hasher.update(&shared_secret.src_id);
    hasher.update(&shared_secret.dst_id);

    let computed_commitment_hash = hasher.finalize();

    if computed_commitment_hash.to_vec() != seed_exchange.commitment.hash {
        print!("Expected: {:?}, got hash: {:?}\n", hex::encode(seed_exchange.commitment.hash), hex::encode(computed_commitment_hash.to_vec()));
        return ProveResult::SlashableError;
    }

    let mut cfst: Vec<G1Affine> = Vec::new();
    for pubkey in &initial_commitment.verification_vector.pubkeys {
        cfst.push(G1Affine::from_compressed(pubkey).into_option().unwrap());
    }


    let mut le_bytes = seed_exchange.shared_secret.dst_id.clone();
    //le_bytes.reverse();

    let id = Scalar::from_bytes(&le_bytes).unwrap();
    for i in 0..cfst.len() {
        print!("cfst[{}]: {:?}\n", i, hex::encode(cfst[i].to_compressed()));
    }
    print!("id: {:?}\n", hex::encode(id.to_bytes()));
    let eval_result = evaluate_polynomial(cfst, id);

    if eval_result != sk.to_public_key().key {
        print!("Expected: {:?}, got pk: {:?}\n", hex::encode(eval_result.to_compressed()), hex::encode(sk.to_public_key().key.to_compressed()));
        return ProveResult::SlashableError;
    }


    ProveResult::Ok
}

pub fn verify_initial_commitment(commitment: &dvt_abi::AbiInitialCommitment) -> ProveResult {
    let mut hasher = Sha256::new();

    hasher.update([commitment.settings.n]);
    hasher.update([commitment.settings.k]);
    hasher.update(commitment.settings.gen_id);
    for pubkey in &commitment.verification_vector.pubkeys {
        hasher.update(&pubkey);
    }

    if hasher.finalize().to_vec() != commitment.hash {
        return ProveResult::SlashableError;
    }

    ProveResult::Ok
}

pub struct PublicKey {
    key: G1Affine
}

pub struct SecretKey {
    key: Scalar
}

impl PublicKey {
    pub fn to_hex(&self) -> String {
        hex::encode(self.key.to_compressed())
    }
}

impl SecretKey {
    pub fn to_public_key(&self) -> PublicKey {
        PublicKey {
            key: G1Affine::from(G1Affine::generator() * self.key)
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<SecretKey, Box<dyn std::error::Error>> {
        let mut le_bytes = bytes.clone();
        le_bytes.reverse();

        let sk = Scalar::from_bytes(&le_bytes);

        if sk.is_none().into() {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid secret key",
            )));
        }

        Ok(SecretKey {
            key: sk.unwrap()
        })
    }
}

pub fn validate_verification_data(verification_vector: &dvt_abi::AbiVerificationVector) -> Result<(), Box<dyn std::error::Error>> {
    // let mut sign_data: Vec<u8> = Vec::new();
    // for pubkey in &verification_vector.pubkeys {
    //     let mut o = pubkey.as_slice().to_vec();
    //     sign_data.append(&mut o);
    // }

    // let mut hasher = Sha256::new();
    // hasher.update(&sign_data);
    // let result = hasher.finalize();

    // if result.to_vec() != verification_vector.hash {
    //     return Err(Box::new(std::io::Error::new(
    //         std::io::ErrorKind::InvalidData,
    //         "Hash verification failed",
    //     )));
    // } else {
    //     println!("Hash verified");
    // }

    // let sig = G2Affine::from_compressed(&verification_vector.signature).into_option()
    //     .ok_or("Failed to decompress signature")?;
    // let pk = G1Affine::from_compressed(&verification_vector.creator_pubkey).into_option()
    //     .ok_or("Failed to decompress creator public key")?;

    // if bls_verify(&pk, &sig, &sign_data) {
    //     println!("Signature verified");
    // } else {
    //     return Err(Box::new(std::io::Error::new(
    //         std::io::ErrorKind::InvalidData,
    //         "Signature verification failed",
    //     )));
    // }

    Ok(())
}

pub fn read_array_from_host<const N: usize>() -> [u8; N] {
    let mut result = [0u8; N];
    for i in 0..N {
        result[i] = sp1_zkvm::io::read();
    }
    result
}

pub fn read_pubkeys_from_host(cnt: u8) -> Vec<[u8; 48]> {
    let mut result = Vec::new();
    for i in 0..cnt {
        result.push(read_array_from_host());
    }
    result
}

pub fn read_settings_from_host() -> dvt_abi::AbiGenerateSettings {
    dvt_abi::AbiGenerateSettings {
        n: sp1_zkvm::io::read(),
        k: sp1_zkvm::io::read(),
        gen_id: read_array_from_host::<16>(),
    }
}

pub fn read_verification_vector_from_host(k: u8) -> dvt_abi::AbiVerificationVector {
    dvt_abi::AbiVerificationVector {
        pubkeys: read_pubkeys_from_host(k),
    }
}

pub fn read_commitment_from_host() -> dvt_abi::AbiCommitment {
    dvt_abi::AbiCommitment {
        hash: read_array_from_host::<32>(),
        pubkey: read_array_from_host::<48>(),
        signature: read_array_from_host::<96>(),
    }
}

pub fn read_initial_commitment_from_host() -> dvt_abi::AbiInitialCommitment {
    let hash = read_array_from_host::<32>();
    let settings = read_settings_from_host();
    let verification_vector = read_verification_vector_from_host(settings.k);
    dvt_abi::AbiInitialCommitment {
        hash: hash,
        settings: settings,
        verification_vector: verification_vector,
    }
}

pub fn read_exchange_secret_from_host() -> dvt_abi::AbiExchangedSecret {
    dvt_abi::AbiExchangedSecret {
        src_id: read_array_from_host::<32>(),
        dst_id: read_array_from_host::<32>(),
        secret: read_array_from_host::<32>(),
    }
}

pub fn read_seeds_exchange_commitment_from_host() -> dvt_abi::AbiSeedExchangeCommitment {
    dvt_abi::AbiSeedExchangeCommitment {
        initial_commitment_hash: read_array_from_host::<32>(),
        shared_secret: read_exchange_secret_from_host(),
        commitment: read_commitment_from_host(),
    }
}

pub fn read_bls_shared_data_from_host() -> dvt_abi::AbiBlsSharedData {
    let inital_commitment = read_initial_commitment_from_host();
    let seeds_exchange_commitment = read_seeds_exchange_commitment_from_host();

    dvt_abi::AbiBlsSharedData {
        initial_commitment: inital_commitment,
        seeds_exchange_commitment: seeds_exchange_commitment,
    }
}
