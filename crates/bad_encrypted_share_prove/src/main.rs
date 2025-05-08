#![no_main]

sp1_zkvm::entrypoint!(main);

use dkg::{self, for_each_raw_type, VerificationErrors};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};

use bls12_381::{self, G1Affine, G2Affine};
use dkg::crypto::*;
use dkg::types::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fmt;

fn new_chacha20_cipher(base: &[u8], _key_salt: &str, _nonce_salt: &str) -> ChaCha20 {
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
    println!("nonce_hash: {}", hex::encode(&nonce_hash[..12]));
    let nonce = Nonce::from_slice(&nonce_hash[..12]);

    ChaCha20::new(key, nonce)
}

mod sealed {
    pub trait Sealed {}
}

pub trait ReadPrimitive: sealed::Sealed + Sized {
    fn from_bytes(bytes: &[u8]) -> Self;
}

impl<T> sealed::Sealed for T where T: for<'a> TryFrom<&'a [u8]> + Sized {}

impl<T> ReadPrimitive for T
where
    T: for<'a> TryFrom<&'a [u8]> + Sized,
{
    fn from_bytes(bytes: &[u8]) -> Self {
        match T::try_from(bytes) {
            Ok(t) => t,
            Err(_) => panic!("Failed to read primitive"),
        }
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

    pub fn finalize(&mut self) {
        assert!(self.pos == self.data.len());
    }
}

fn parse_message<Setup: dkg::DkgSetup + dkg::DkgSetupTypes<Setup>>(
    msg: &[u8],
    settings: dkg::GenerateSettings,
    base_pubkeys: Vec<RawBytes<Setup::Point>>,
    commitment_hashes: Vec<SHA256Raw>,
    receiver_commitment_hash: SHA256Raw,
) -> Result<dkg::SharedData<Setup>, String> {
    let mut stream = BinaryStream {
        data: msg.to_vec(),
        pos: 0,
    };

    let gen_id = stream
        .read_byte_array::<{ GEN_ID_SIZE }>()
        .map_err(|e| format!("Invalid gen_id: {e}"))?;
    let _msg_type = stream
        .read_byte_array::<1>()
        .map_err(|e| format!("Invalid msg_type: {e}"))?[0];
    let secret = stream
        .read::<RawBytes<Setup::DkgSecretKey>>()
        .map_err(|e| format!("Invalid secret: {e}"))?;
    let commitment_hash = stream
        .read_byte_array::<{ SHA256_SIZE }>()
        .map_err(|e| format!("Invalid commitment_hash: {e}"))?;
    let commitment_pubkey = stream
        .read::<RawBytes<Setup::CommitmentPubkey>>()
        .map_err(|e| format!("Invalid commitment_pubkey: {e}"))?;
    let commitment_signature = stream
        .read::<RawBytes<Setup::CommitmentSignature>>()
        .map_err(|e| format!("Invalid commitment_signature: {e}"))?;

    stream.finalize();

    let mut initial_commitment = dkg::InitialCommitment::<Setup> {
        settings: settings,
        base_pubkeys: base_pubkeys,
        hash: SHA256Raw([0u8; SHA256_SIZE]),
    };

    let initial_commitment_hash =
        dkg::compute_initial_commitment_hash::<Setup>(&initial_commitment);

    initial_commitment.hash = initial_commitment_hash.clone();
    println!("gen_id {}", hex::encode(&gen_id));
    println!("_msg_type {}", hex::encode(&[_msg_type]));
    println!("secret {}", &secret);
    println!("commitment_hash {}", hex::encode(&commitment_hash));
    println!("commitment_pubkey {}", &commitment_pubkey);
    println!("commitment_signature {}", &commitment_signature);
    Ok(dkg::SharedData::<Setup> {
        verification_hashes: commitment_hashes,
        initial_commitment: initial_commitment,
        seeds_exchange_commitment: dkg::SeedExchangeCommitment {
            initial_commitment_hash: initial_commitment_hash,
            shared_secret: dkg::ExchangedSecret {
                secret: secret,
                dst_base_hash: receiver_commitment_hash,
            },
            commitment: dkg::Commitment {
                hash: SHA256Raw(commitment_hash),
                pubkey: commitment_pubkey,
                signature: commitment_signature,
            },
        },
    })
}

pub fn main() {
    run::<BlsDkgWithSecp256kCommitment>();
}

pub fn run<Setup>()
where
    Setup: dkg::DkgSetup + dkg::DkgSetupTypes<Setup> + for<'a> Deserialize<'a>,
{
    let input: Vec<u8> = sp1_zkvm::io::read();
    let data: dkg::BadEncryptedShare<Setup> =
        serde_cbor::from_slice(&input).expect("Failed to deserialize share data");

    let our = Setup::Scalar::from_bytes(&data.receiver_encr_seckey).unwrap();
    let their = Setup::Point::from_bytes(&data.sender_encr_pubkey).unwrap();

    let p = their.mul_scalar(&our);

    let mut cipher2 = new_chacha20_cipher(&p.to_bytes().as_arr(), "", "");

    let mut decrypted =
        hex::decode(&data.encrypted_message).expect("invalid hex in encrypted_message");
    cipher2.apply_keystream(&mut decrypted);
    println!("decrypted {:?}", hex::encode(&decrypted));
    let data = match parse_message::<Setup>(
        &decrypted,
        data.settings,
        data.base_pubkeys,
        data.base_hashes,
        data.receiver_commitment_hash,
    ) {
        Ok(data) => data,
        Err(e) => {
            println!("Error: {}", e);
            sp1_zkvm::io::commit(&data.encrypted_message);
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
            "The seed exchange commitment hash {} is not part of the verification hashes  {} \n",
            data.initial_commitment.hash,
            data.verification_hashes
                .iter()
                .map(|h| h.to_hex())
                .collect::<Vec<String>>()
                .join(", ")
        );
    }

    if !dkg::verify_initial_commitment_hash::<Setup>(&data.initial_commitment) {
        panic!("Unsalshable error while verifying commitment hash\n");
    }

    match dkg::verify_seed_exchange_commitment::<Setup>(
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
                            println!("Verification hash: {}", h);
                            sp1_zkvm::io::commit(h.as_ref());
                        }

                        println!(
                            "Perpetrator public key: {}",
                            data.seeds_exchange_commitment.commitment.pubkey
                        );
                        for byte in data
                            .seeds_exchange_commitment
                            .commitment
                            .pubkey
                            .as_arr()
                            .iter()
                        {
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
