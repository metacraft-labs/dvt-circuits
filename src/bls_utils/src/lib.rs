use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve}, pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar   
};

use sha2::{Sha256};

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
