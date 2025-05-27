#![no_main]

sp1_zkvm::entrypoint!(main);

use dkg::{self, compute_initial_commitment_hash};

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::{ChaCha20, Key, Nonce};

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
    let key = Key::from_slice(&key_hash[..32]);

    let mut nonce_hasher = Sha256::new();
    nonce_hasher.update(base);
    //nonce_hasher.update(nonce_salt.as_bytes());
    let nonce_hash = nonce_hasher.finalize();
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
        let bytes = self.data[self.pos..self.pos + N]
            .try_into()
            .expect("Invalid length");
        self.pos += N;
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
        Ok(T::from_bytes(bytes))
    }

    pub fn remain_len(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn finalize(&mut self) {
        println!(
            "Read {} bytes, {} remain",
            self.pos,
            self.data.len() - self.pos
        );
        assert!(self.pos == self.data.len());
    }
}

#[cfg(feature = "auth_commitment")]
fn parse_message<Setup: dkg::DkgSetup + dkg::DkgSetupTypes<Setup>>(
    msg: Vec<u8>,
    settings: dkg::GenerateSettings,
    base_pubkeys: Vec<RawBytes<Setup::Point>>,
    commitment_hashes: Vec<SHA256Raw>,
    receiver_commitment_hash: SHA256Raw,
    sender_commitment_hash: SHA256Raw,
) -> Result<dkg::SharedData<Setup>, String> {
    let mut stream = BinaryStream { data: msg, pos: 0 };

    let gen_id = stream
        .read::<DkgGenId>()
        .map_err(|e| format!("Invalid gen_id: {e}"))?;

    println!("remain_len {}", stream.remain_len());
    let msg_type = stream
        .read_byte_array::<1>()
        .map_err(|e| format!("Invalid msg_type: {e}"))?[0];
    println!("remain_len {}", stream.remain_len());
    let secret = stream
        .read::<RawBytes<Setup::DkgSecretKey>>()
        .map_err(|e| format!("Invalid secret: {e}"))?;
    println!("remain_len {}", stream.remain_len());
    let commitment_hash = stream
        .read::<SHA256Raw>()
        .map_err(|e| format!("Invalid commitment_hash: {e}"))?;
    println!("remain_len {}", stream.remain_len());
    let commitment_pubkey = stream
        .read::<RawBytes<Setup::CommitmentPubkey>>()
        .map_err(|e| format!("Invalid commitment_pubkey: {e}"))?;
    println!("remain_len {}", stream.remain_len());
    let commitment_signature = stream
        .read::<RawBytes<Setup::CommitmentSignature>>()
        .map_err(|e| format!("Invalid commitment_signature: {e}"))?;
    println!("remain_len {}", stream.remain_len());

    stream.finalize();

    if stream.bytes_left() != 0 {
        return Err("Invalid message".to_string());
    }

    if settings.gen_id != gen_id {
        return Err("Invalid gen_id".to_string());
    }

    if msg_type != 3 {
        return Err("Invalid msg_type".to_string());
    }

    let initial_commitment = dkg::InitialCommitment::<Setup> {
        settings: settings,
        base_pubkeys: base_pubkeys,
        hash: sender_commitment_hash.clone(),
    };

    Ok(dkg::SharedData::<Setup> {
        verification_hashes: commitment_hashes,
        initial_commitment: initial_commitment,
        seeds_exchange_commitment: dkg::SeedExchangeCommitment {
            initial_commitment_hash: sender_commitment_hash,
            shared_secret: dkg::ExchangedSecret {
                secret: secret,
                dst_base_hash: receiver_commitment_hash,
            },
            commitment: dkg::Commitment {
                hash: commitment_hash,
                pubkey: commitment_pubkey,
                signature: commitment_signature,
            },
        },
    })
}

#[cfg(not(feature = "auth_commitment"))]
fn parse_message<Setup: dkg::DkgSetup + dkg::DkgSetupTypes<Setup>>(
    msg: Vec<u8>,
    settings: dkg::GenerateSettings,
    base_pubkeys: Vec<RawBytes<Setup::Point>>,
    commitment_hashes: Vec<SHA256Raw>,
    receiver_commitment_hash: SHA256Raw,
    sender_commitment_hash: SHA256Raw,
) -> Result<dkg::SharedData<Setup>, String> {
    let mut stream = BinaryStream { data: msg, pos: 0 };

    let gen_id = stream
        .read::<DkgGenId>()
        .map_err(|e| format!("Invalid gen_id: {e}"))?;
    //println!("remain_len {}", stream.remain_len());
    let msg_type = stream
        .read_byte_array::<1>()
        .map_err(|e| format!("Invalid msg_type: {e}"))?[0];
    //println!("remain_len {}", stream.remain_len());
    let secret = stream
        .read::<RawBytes<Setup::DkgSecretKey>>()
        .map_err(|e| format!("Invalid secret: {e}"))?;
    //println!("remain_len {}", stream.remain_len());
    let commitment_pubkey = stream
        .read::<RawBytes<Setup::CommitmentPubkey>>()
        .map_err(|e| format!("Invalid commitment_pubkey: {e}"))?;
    //println!("remain_len {}", stream.remain_len());
    stream.finalize();

    if stream.bytes_left() != 0 {
        return Err("Invalid message".to_string());
    }

    if settings.gen_id != gen_id {
        return Err("Invalid gen_id".to_string());
    }

    if msg_type != 3 {
        return Err("Invalid msg_type".to_string());
    }

    let initial_commitment = dkg::InitialCommitment::<Setup> {
        settings: settings,
        base_pubkeys: base_pubkeys,
        hash: sender_commitment_hash.clone(),
    };

    Ok(dkg::SharedData::<Setup> {
        verification_hashes: commitment_hashes,
        initial_commitment: initial_commitment,
        seeds_exchange_commitment: dkg::SeedExchangeCommitment {
            initial_commitment_hash: sender_commitment_hash,
            shared_secret: dkg::ExchangedSecret {
                secret: secret,
                dst_base_hash: receiver_commitment_hash,
            },
            commitment: dkg::Commitment {
                pubkey: commitment_pubkey,
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

    let sender_commitment_hash =
        compute_initial_commitment_hash::<Setup>(&data.settings, &data.sender_base_pubkeys);

    if !data
        .base_hashes
        .iter()
        .any(|h| h == &sender_commitment_hash)
    {
        panic!("Invalid sender_commitment_hash {}", sender_commitment_hash);
    }

    let receiver_commitment_hash =
        compute_initial_commitment_hash::<Setup>(&data.settings, &data.receiver_base_pubkeys);

    if !data
        .base_hashes
        .iter()
        .any(|h| h == &receiver_commitment_hash)
    {
        panic!(
            "Invalid receiver_commitment_hash {}",
            receiver_commitment_hash
        );
    }

    let mut keys = data.receiver_base_pubkeys.clone();
    keys.sort();

    if Setup::DkgSecretKey::from_bytes(&data.receiver_encr_seckey)
        .expect("Invalid seckey")
        .to_public_key()
        .to_bytes()
        != keys[keys.len() - 1]
    {
        panic!("Invalid seckey");
    };

    if data.base_hashes.len() != data.settings.n as usize {
        panic!("The number of verification hashes does not match the number of keys\n");
    }

    if data.settings.n < data.settings.k {
        panic!("N should be greater than or equal to k\n");
    }

    let our = Setup::Scalar::from_bytes(&data.receiver_encr_seckey).expect("Invalid seckey");
    let their = Setup::Point::from_bytes(&data.sender_encr_pubkey).expect("Invalid pubkey");

    let p = their.mul_scalar(&our);

    let mut cipher2 = new_chacha20_cipher(&p.to_bytes().as_arr(), "", "");

    let encrypted_bytes =
        hex::decode(&data.encrypted_message).expect("invalid hex in encrypted_message");
    let mut decrypted = encrypted_bytes.clone();
    cipher2.apply_keystream(&mut decrypted);
    let shared_data = match parse_message::<Setup>(
        decrypted,
        data.settings,
        data.sender_base_pubkeys,
        data.base_hashes,
        receiver_commitment_hash,
        sender_commitment_hash,
    ) {
        Ok(data) => data,
        Err(e) => {
            println!("Error: {}", e);
            sp1_zkvm::io::commit(&sender_commitment_hash);
            sp1_zkvm::io::commit(&receiver_commitment_hash);
            sp1_zkvm::io::commit(&data.encrypted_message);
            return;
        }
    };

    if !dkg::verify_initial_commitment_hash::<Setup>(&shared_data.initial_commitment) {
        panic!("Unsalshable error while verifying commitment hash\n");
    }

    match dkg::verify_seed_exchange_commitment::<Setup>(
        &shared_data.verification_hashes,
        &shared_data.seeds_exchange_commitment,
        &shared_data.initial_commitment,
    ) {
        Ok(()) => {
            println!("The share is valid. We can't that the prove participant share is corrupted.");
        }

        Err(e) => {
            println!("Slashable error seed exchange commitment: {}", e);

            println!(
                "Perpetrator public key: {}\n Sender commitment hash: {}\n Receiver commitment hash: {}",
                shared_data.seeds_exchange_commitment.commitment.pubkey,
                sender_commitment_hash,
                receiver_commitment_hash,
            );

            sp1_zkvm::io::commit(&sender_commitment_hash);
            sp1_zkvm::io::commit(&receiver_commitment_hash);
            sp1_zkvm::io::commit(&encrypted_bytes);
        }
    }
    panic!("The seed exchange commitment is valid");
}
