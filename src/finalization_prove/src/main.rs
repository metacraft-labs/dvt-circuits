#![no_main]

use std::ptr::hash;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve}, pairing, G1Affine, G1Projective, G2Affine, G2Projective, Scalar
    
};
use dvt_abi::{AbiBlsSharedData, AbiVerificationVector, DvtGenerateSettings};
use sha2::{Sha256, Digest};
sp1_zkvm::entrypoint!(main);

use bls_utils::{evaluate_polynomial, bls_verify};



pub fn main() {
    panic!();
}
