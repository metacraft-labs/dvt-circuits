use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve}, pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar   
};

use sha2::{Sha256, Digest};
use dvt_abi::AbiVerificationVector;

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

pub fn validate_verification_data(verification_vector: &AbiVerificationVector) -> Result<(), Box<dyn std::error::Error>> {
    let mut sign_data: Vec<u8> = Vec::new();
    for pubkey in &verification_vector.pubkeys {
        let mut o = pubkey.as_slice().to_vec();
        sign_data.append(&mut o);
    }

    let mut hasher = Sha256::new();
    hasher.update(&sign_data);
    let result = hasher.finalize();

    if result.to_vec() != verification_vector.hash {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Hash verification failed",
        )));
    } else {
        println!("Hash verified");
    }

    let sig = G2Affine::from_compressed(&verification_vector.signature).into_option()
        .ok_or("Failed to decompress signature")?;
    let pk = G1Affine::from_compressed(&verification_vector.creator_pubkey).into_option()
        .ok_or("Failed to decompress creator public key")?;

    if bls_verify(&pk, &sig, &sign_data) {
        println!("Signature verified");
    } else {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Signature verification failed",
        )));
    }

    Ok(())
}

