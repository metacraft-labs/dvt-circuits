fn main() {
    sp1_build::build_program("crates/share_exchange_prove");
    sp1_build::build_program("crates/finalization_prove");
    sp1_build::build_program("crates/bad_parial_key_prove");
    sp1_build::build_program("crates/bad_encrypted_share_prove");
}
