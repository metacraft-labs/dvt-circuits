#![no_main]

sp1_zkvm::entrypoint!(main);

use bls_utils::{self};

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;

use bls12_381::{self, G1Affine, G1Projective};

pub fn main() {
    let data = bls_utils::read_bad_encrypted_share();
    println!("{:?}", data);

    let g1 = bls12_381::G1Affine::from_compressed(&data.sender_pubkey).unwrap();
    let mut le_bytes = data.receiver_secret_key.clone();
    le_bytes.reverse();

    let sk = bls12_381::Scalar::from_bytes(&le_bytes).unwrap();

    let composite_key = G1Projective::from(g1) * sk;
    let compresed = G1Affine::from(composite_key).to_compressed();
}
