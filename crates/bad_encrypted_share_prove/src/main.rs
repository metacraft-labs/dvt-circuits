#![no_main]

sp1_zkvm::entrypoint!(main);

use std::result;

use bls_utils::{self, bls, VerificationErrors};

use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{ChaCha20, Key, Nonce};

use bls12_381::{self, G1Affine, G1Projective, G2Affine};
use sha2::{Digest, Sha256};
use std::fmt;

fn new_chacha20_cipher(base: &[u8], key_salt: &str, nonce_salt: &str) -> ChaCha20 {
    let mut key_hasher = Sha256::new();
    key_hasher.update(base);
    //key_hasher.update(key_salt.as_bytes());
    let key_hash = key_hasher.finalize();
    println!("key_hash: {}", hex::encode(key_hash));
    let key = Key::from_slice(&key_hash[..32]);

    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(base);
    //nonce_hasher.update(nonce_salt.as_bytes());
    let nonce_hash = nonce_hasher.finalize();
    println!("nonce_hash: {}", hex::encode(nonce_hash));
    let nonce = Nonce::from_slice(&nonce_hash[..12]);

    ChaCha20::new(key, nonce)
}

mod sealed {
    pub trait Sealed {}
}

pub trait ReadPrimitive: sealed::Sealed + Sized {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl sealed::Sealed for u8 {}
impl ReadPrimitive for u8 {
    fn from_bytes(bytes: &[u8]) -> Self {
        bytes[0]
    }
}

impl sealed::Sealed for i8 {}
impl ReadPrimitive for i8 {
    fn from_bytes(bytes: &[u8]) -> Self {
        bytes[0] as i8
    }
}

impl sealed::Sealed for u16 {}
impl ReadPrimitive for u16 {
    fn from_bytes(bytes: &[u8]) -> Self {
        u16::from_le_bytes(bytes.try_into().unwrap())
    }
}

impl sealed::Sealed for i16 {}
impl ReadPrimitive for i16 {
    fn from_bytes(bytes: &[u8]) -> Self {
        i16::from_le_bytes(bytes.try_into().unwrap())
    }
}

impl sealed::Sealed for u32 {}
impl ReadPrimitive for u32 {
    fn from_bytes(bytes: &[u8]) -> Self {
        u32::from_le_bytes(bytes.try_into().unwrap())
    }
}

impl sealed::Sealed for i32 {}
impl ReadPrimitive for i32 {
    fn from_bytes(bytes: &[u8]) -> Self {
        i32::from_le_bytes(bytes.try_into().unwrap())
    }
}

#[derive(Debug)]
pub enum ReadError {
    NotEnoughBytes {
        pos: usize,
        needed: usize,
        remain: usize,
    },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::NotEnoughBytes {
                pos,
                needed,
                remain,
            } => write!(
                f,
                "Not enough bytes at position {}, needed {}, but only {} remain.",
                pos, needed, remain
            ),
        }
    }
}

impl std::error::Error for ReadError {}

pub struct BinaryStream {
    data: Vec<u8>,
    pos: usize,
}

impl BinaryStream {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    fn bytes_left(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn read_byte_array<const N: usize>(&mut self) -> Result<[u8; N], ReadError> {
        if self.bytes_left() < N {
            // Slice a portion of the data that remains (up to N or the end)
            let end = (self.pos + N).min(self.data.len());

            return Err(ReadError::NotEnoughBytes {
                pos: self.pos,
                needed: N,
                remain: self.bytes_left(),
            });
        }
        let bytes = self.data[self.pos..self.pos + N].try_into().unwrap();
        self.pos += N;
        println!("Read bytes: {}", hex::encode(&bytes));
        Ok(bytes)
    }

    pub fn read<T: ReadPrimitive>(&mut self) -> Result<T, ReadError> {
        let size = std::mem::size_of::<T>();
        if self.bytes_left() < size {
            return Err(ReadError::NotEnoughBytes {
                pos: self.pos,
                needed: size,
                remain: self.bytes_left(),
            });
        }
        let bytes = &self.data[self.pos..self.pos + size];
        self.pos += size;
        println!("Read bytes: {}", hex::encode(bytes));
        Ok(T::from_bytes(bytes))
    }
}

fn parse_message(msg: &[u8]) -> Result<dvt_abi::AbiBlsSharedData, String> {
    let mut stream = BinaryStream {
        data: msg.to_vec(),
        pos: 0,
    };
    let msg_type = stream
        .read::<u8>()
        .map_err(|e| format!("Invalid message type: {e}"))?;

    let hash_count = stream
        .read::<u8>()
        .map_err(|e| format!("Invalid hash count: {e}"))?;
    let mut commitment_hashes = Vec::new();
    for i in 0..hash_count {
        commitment_hashes.push(
            stream
                .read_byte_array::<{ dvt_abi::SHA256_SIZE }>()
                .map_err(|e| format!("Invalid commitment hash (at index {i}): {e}"))?,
        );
    }

    let n = stream.read::<u8>().map_err(|e| format!("Invalid n: {e}"))?;
    let k = stream.read::<u8>().map_err(|e| format!("Invalid k: {e}"))?;
    let settings = dvt_abi::AbiGenerateSettings {
        n: n,
        k: k,
        gen_id: stream
            .read_byte_array::<{ dvt_abi::GEN_ID_SIZE }>()
            .map_err(|e| format!("Invalid gen_id: {e}"))?,
    };

    let k = stream.read::<u8>().map_err(|e| format!("Invalid k: {e}"))?;

    let mut base_pubkeys = Vec::new();
    for i in 0..k {
        base_pubkeys.push(
            stream
                .read_byte_array::<{ dvt_abi::BLS_PUBKEY_SIZE }>()
                .map_err(|e| format!("Invalid base_pubkey (at index {i}): {e}"))?,
        );
        println!("base_pubkey: {}", i);
    }

    let settings_hash_1 = stream
        .read_byte_array::<{ dvt_abi::SHA256_SIZE }>()
        .map_err(|e| format!("Invalid settings hash 1: {e}"))?;

    let commitment_shash_2 = stream
        .read_byte_array::<{ dvt_abi::SHA256_SIZE }>()
        .map_err(|e| format!("Invalid commitment_shash_2: {e}"))?;

    let shared_secret = stream
        .read_byte_array::<{ dvt_abi::BLS_SECRET_SIZE }>()
        .map_err(|e| format!("Invalid shared_secret: {e}"))?;
    let receiver_base_hash = stream
        .read_byte_array::<{ dvt_abi::SHA256_SIZE }>()
        .map_err(|e| format!("Invalid receiver_base_hash: {e}"))?;
    println!("receiver_base_hash: {}", hex::encode(receiver_base_hash));
    let sender_share_id = stream
        .read_byte_array::<{ dvt_abi::BLS_ID_SIZE }>()
        .map_err(|e| format!("Invalid sender_share_id: {e}"))?;
    let receiver_share_id = stream
        .read_byte_array::<{ dvt_abi::BLS_ID_SIZE }>()
        .map_err(|e| format!("Invalid receiver_share_id: {e}"))?;

    let shared_secret_hash = stream
        .read_byte_array::<{ dvt_abi::SHA256_SIZE }>()
        .map_err(|e| format!("Invalid shared_secret_hash: {e}"))?;
    let sender_pubkey = stream
        .read_byte_array::<{ dvt_abi::BLS_PUBKEY_SIZE }>()
        .map_err(|e| format!("Invalid sender_pubkey: {e}"))?;
    let signature = stream
        .read_byte_array::<{ dvt_abi::BLS_SIGNATURE_SIZE }>()
        .map_err(|e| format!("Invalid signature: {e}"))?;

    Ok(dvt_abi::AbiBlsSharedData {
        verification_hashes: commitment_hashes,
        initial_commitment: dvt_abi::AbiInitialCommitment {
            settings: settings,
            verification_vector: dvt_abi::AbiVerificationVector {
                pubkeys: base_pubkeys,
            },
            hash: settings_hash_1,
        },
        seeds_exchange_commitment: dvt_abi::AbiSeedExchangeCommitment {
            initial_commitment_hash: commitment_shash_2,
            shared_secret: dvt_abi::AbiExchangedSecret {
                src_id: sender_share_id,
                dst_id: receiver_share_id,
                secret: shared_secret,
                dst_base_hash: receiver_base_hash,
            },
            commitment: dvt_abi::AbiCommitment {
                hash: shared_secret_hash,
                pubkey: sender_pubkey,
                signature: signature,
            },
        },
    })
}

pub fn main() {
    let data = bls_utils::read_bad_encrypted_share();
    // println!("{:?}", data.signature);
    // println!("{:?}", data.receiver_pubkey);

    let pk = G1Affine::from_compressed(&data.sender_pubkey)
        .into_option()
        .unwrap();
    let sig = G2Affine::from_compressed(&data.signature)
        .into_option()
        .unwrap();

    let p = bls12_381::pairing(&pk, &sig);

    //print!("{:?}", hex::encode(p.to_bytes()));

    println!("pk:: {:?}", hex::encode(pk.to_compressed()));
    println!("sig:: {:?}", hex::encode(sig.to_compressed()));
    println!("pairing:: {:?}", hex::encode(p.to_bytes_raw()));

    let mut cipher2 = new_chacha20_cipher(p.to_bytes_raw().as_slice(), "", "");

    let mut descrypted = data.encrypted_message.clone();
    cipher2.apply_keystream(&mut descrypted);
    println!("decrypted {:?}", hex::encode(&descrypted));

    let data = match parse_message(&descrypted) {
        Ok(data) => data,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    if data.verification_hashes.len() != data.initial_commitment.settings.n as usize {
        panic!("The number of verification hashes does not match the number of keys\n");
    }

    if data.initial_commitment.settings.n < data.initial_commitment.settings.k {
        panic!("N should be greater than or equal to k\n");
    }

    let found = data
        .verification_hashes
        .iter()
        .any(|h| h == &data.initial_commitment.hash);

    if !found {
        panic!(
            "The seed exchange commitment is not part of the verification hashes {} \n",
            hex::encode(data.initial_commitment.hash)
        );
    }

    if !bls_utils::verify_initial_commitment_hash(&data.initial_commitment) {
        panic!("Unsalshable error while verifying commitment hash\n");
    }

    match bls_utils::verify_seed_exchange_commitment(
        &data.verification_hashes,
        &data.seeds_exchange_commitment,
        &data.initial_commitment,
    ) {
        Ok(()) => {
            println!("The share is valid. We can't that the prove participant share is corrupted.");
        }

        Err(e) => {
            if let Some(verification_error) = e.downcast_ref::<VerificationErrors>() {
                match verification_error {
                    VerificationErrors::SlashableError(err) => {
                        println!("Slashable error seed exchange commitment: {}", err);

                        for h in data.verification_hashes.iter() {
                            println!("Verification hash: {}", hex::encode(h));
                            sp1_zkvm::io::commit(h);
                        }

                        println!(
                            "Perpetrator public key: {}",
                            hex::encode(data.seeds_exchange_commitment.commitment.pubkey)
                        );
                        for byte in data.seeds_exchange_commitment.commitment.pubkey {
                            sp1_zkvm::io::commit(&byte);
                        }

                        return;
                    }
                    VerificationErrors::UnslashableError(err) => {
                        panic!("Unslashable error seed exchange commitment: {}", err);
                    }
                }
            } else {
                panic!("Unknown error seed exchange commitment: {}", e);
            }
        }
    }
    panic!("The seed exchange commitment is valid");
}
