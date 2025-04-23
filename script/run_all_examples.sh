#!/usr/bin/env bash

# Get the repository root directory
REPO_ROOT=$(git rev-parse --show-toplevel)
if [ $? -ne 0 ]; then
    echo "Error: Not inside a git repository."
    exit 1
fi


cargo  build --release
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo -e "${RED}Error: Cargo build failed.${RESET}"
    exit 1
fi

HOST_BIN_PATH=target/release/dkg_prover_host 

$HOST_BIN_PATH execute --type bad-share -i $REPO_ROOT/examples/dkg_bad_share.json  --show-report --json-schema-file $REPO_ROOT/spec/share_exchange_spec.json
$HOST_BIN_PATH execute --type bad-encrypted-share -i $REPO_ROOT/examples/bad_encrypted_bad_share.json  --show-report --json-schema-file $REPO_ROOT/spec/bad_encrypted_partial_key_spec.json
$HOST_BIN_PATH execute --type bad-partial-key -i $REPO_ROOT/examples/bad_partial_key.json  --show-report --json-schema-file $REPO_ROOT/spec/bad_partial_key_spec.json
$HOST_BIN_PATH execute --type finalization -i $REPO_ROOT/examples/finalization_test.json  --show-report --json-schema-file $REPO_ROOT/spec/finalization_spec.json
