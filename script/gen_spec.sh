#!/usr/bin/env bash

# Get the repository root directory
REPO_ROOT=$(git rev-parse --show-toplevel)
if [ $? -ne 0 ]; then
    echo "Error: Not inside a git repository."
    exit 1
fi


cargo  build --release --features auth_commitment
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo -e "${RED}Error: Cargo build failed.${RESET}"
    exit 1
fi

HOST_BIN_PATH=target/release/dkg_prover_host 


$HOST_BIN_PATH get-schema --type bad-share --schema-type json -o $REPO_ROOT/spec/json/share_exchange_spec.json
$HOST_BIN_PATH get-schema --type bad-encrypted-share --schema-type json -o $REPO_ROOT/spec/json/bad_encrypted_partial_key_spec.json
$HOST_BIN_PATH get-schema --type bad-partial-key --schema-type json -o $REPO_ROOT/spec/json/bad_partial_key_spec.json
$HOST_BIN_PATH get-schema --type finalization --schema-type json -o $REPO_ROOT/spec/json/finalization_spec.json


$HOST_BIN_PATH get-schema --type bad-share --schema-type yaml -o $REPO_ROOT/spec/yaml/share_exchange_spec.yaml
$HOST_BIN_PATH get-schema --type bad-encrypted-share --schema-type yaml -o $REPO_ROOT/spec/yaml/bad_encrypted_partial_key_spec.yaml
$HOST_BIN_PATH get-schema --type bad-partial-key --schema-type yaml -o $REPO_ROOT/spec/yaml/bad_partial_key.yaml
$HOST_BIN_PATH get-schema --type finalization --schema-type yaml -o $REPO_ROOT/spec/yaml/finalization.yaml