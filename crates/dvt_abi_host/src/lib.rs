use dvt_abi;
use sp1_sdk::SP1Stdin;
fn write_array_to_prover<const N: usize>(stdin: &mut SP1Stdin, data: &[u8; N]) {
    for i in 0..N {
        stdin.write(&[data[i]]);
    }
}
pub trait ProverSerialize {
    fn write(&self, stdin: &mut SP1Stdin);
}

impl ProverSerialize for dvt_abi::AbiGenerateSettings {
    fn write(&self, stdin: &mut SP1Stdin) {
        stdin.write(&[self.n]);
        stdin.write(&[self.k]);
        write_array_to_prover(stdin, &self.gen_id);
    }
}

impl ProverSerialize for dvt_abi::AbiVerificationVector {
    fn write(&self, stdin: &mut SP1Stdin) {
        for i in 0..self.pubkeys.len() {
            write_array_to_prover(stdin, &self.pubkeys[i]);
        }
    }
}

impl ProverSerialize for dvt_abi::AbiInitialCommitment {
    fn write(&self, stdin: &mut SP1Stdin) {
        write_array_to_prover(stdin, &self.hash);
        self.settings.write(stdin);
        self.verification_vector.write(stdin);
    }
}

impl ProverSerialize for dvt_abi::AbiExchangedSecret {
    fn write(&self, stdin: &mut SP1Stdin) {
        write_array_to_prover(stdin, &self.src_id);
        write_array_to_prover(stdin, &self.dst_id);
        write_array_to_prover(stdin, &self.secret);
        write_array_to_prover(stdin, &self.dst_base_hash);
    }
}

impl ProverSerialize for dvt_abi::AbiCommitment {
    fn write(&self, stdin: &mut SP1Stdin) {
        write_array_to_prover(stdin, &self.hash);
        write_array_to_prover(stdin, &self.pubkey);
        write_array_to_prover(stdin, &self.signature);
    }
}

impl ProverSerialize for dvt_abi::AbiSeedExchangeCommitment {
    fn write(&self, stdin: &mut SP1Stdin) {
        write_array_to_prover(stdin, &self.initial_commitment_hash);
        self.shared_secret.write(stdin);
        self.commitment.write(stdin);
    }
}

impl ProverSerialize for dvt_abi::AbiBlsSharedData {
    fn write(&self, stdin: &mut SP1Stdin) {
        self.initial_commitment.write(stdin);
        self.seeds_exchange_commitment.write(stdin);
        if (self.initial_commitment.settings.n as usize) != self.verification_hashes.len() {
            panic!("k != verification_hashes.len() {}", self.verification_hashes.len());
        }
        self.verification_hashes.write(stdin);
    }
}

impl ProverSerialize for dvt_abi::AbiVerificationHashes {
    fn write(&self, stdin: &mut SP1Stdin) {
        for i in 0..self.len() {
            write_array_to_prover(stdin, &self[i]);
        }
    }
}

impl ProverSerialize for dvt_abi::AbiGeneration {
    fn write(&self, stdin: &mut SP1Stdin) {
        for i in 0..self.verification_vector.len() {
            write_array_to_prover(stdin, &self.verification_vector[i]);
        }
        write_array_to_prover(stdin, &self.base_hash);
        write_array_to_prover(stdin, &self.partial_pubkey);
        stdin.write(&(self.message_cleartext.len() as u32));

        for i in 0..self.message_cleartext.len() {
            stdin.write(&self.message_cleartext[i]);
        }
        //stdin.write(self.message_cleartext.as_bytes());
        write_array_to_prover(stdin, &self.message_signature);
    }
}

impl ProverSerialize for dvt_abi::AbiFinalizationData {
    fn write(&self, stdin: &mut SP1Stdin) {
        self.settings.write(stdin);
        if self.settings.n as usize != self.generations.len() {
            panic!("k != generations.len() {}", self.generations.len());
        }
        
        for i in 0..self.generations.len() {
            self.generations[i].write(stdin);
        }
        write_array_to_prover(stdin, &self.aggregate_pubkey);
    }
}

impl ProverSerialize for dvt_abi::AbiWrongFinalKeyGeneration {
    fn write(&self, stdin: &mut SP1Stdin) {
        self.settings.write(stdin);
        for i in 0..self.generations.len() {
            self.generations[i].write(stdin);
        }
        write_array_to_prover(stdin, &self.perpatrator_hash);
    }
}