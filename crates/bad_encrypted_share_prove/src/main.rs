#![no_main]

sp1_zkvm::entrypoint!(main);

use core::panic;

use bls_utils::{self};

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;

pub fn main() {
    let data = bls_utils::read_wrong_final_key_generation_data();
    print!("{:?}", data);

    let ok = bls_utils::prove_wrong_final_key_generation(&data);
    if ok.is_err() {
        panic!("{:?}", ok.unwrap_err().to_string());
    }

    let key = [0x42; 32];
    let nonce = [0x24; 12];
    let plaintext = hex::decode("000102030405060708090A0B0C0D0E0F").unwrap();
    let ciphertext = hex::decode("e405626e4f1236b3670ee428332ea20e").unwrap();

    // Key and IV must be references to the `GenericArray` type.
    // Here we use the `Into` trait to convert arrays into it.
    let mut cipher = ChaCha20::new(&key.into(), &nonce.into());

    let mut buffer = plaintext.clone();

    // apply keystream (encrypt)
    cipher.apply_keystream(&mut buffer);
    assert_eq!(buffer, ciphertext);

    let ciphertext = buffer.clone();

    // ChaCha ciphers support seeking
    cipher.seek(0u32);

    // decrypt ciphertext by applying keystream again
    cipher.apply_keystream(&mut buffer);
    assert_eq!(buffer, plaintext);

    // stream ciphers can be used with streaming messages
    cipher.seek(0u32);
    for chunk in buffer.chunks_mut(3) {
        cipher.apply_keystream(chunk);
    }
    assert_eq!(buffer, ciphertext);
    print!("{:?}", ciphertext);
}
