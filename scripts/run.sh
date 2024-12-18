#!/usr/bin/env bash

# Get the repository root directory
REPO_ROOT=$(git rev-parse --show-toplevel)
if [ $? -ne 0 ]; then
    echo "Error: Not inside a git repository."
    exit 1
fi

# Configuration
TEST_DIR="$REPO_ROOT/test_vectors"   # The directory where your .json test files are located

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
BLUE="\e[34m"
BOLD="\e[1m"
RESET="\e[0m"

# Counters (global)
pass_count=0
fail_count=0

# Function to run tests in a given directory
# Arguments:
#   1: directory containing test files
#   2: test type ("positive" or "negative")
run_tests_in_dir() {
    local dir=$1
    local type=$2

    # Find all JSON test files in the directory
    local test_files=($(find "$dir" -type f -name "*.json"))
    if [ ${#test_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}No JSON test files found in $dir.${RESET}"
        return
    fi

    for test_file in "${test_files[@]}"; do
        test_name=$(basename "$test_file")
        # Run the program
        cargo run --release -- --execute --input-file "$test_file"
        exit_code=$?

        if [[ "$type" == "negative" ]]; then
            # Negative test should fail (non-zero exit)
            if [ $exit_code -ne 0 ]; then
                echo -e "${GREEN}[PASS]${RESET} (negative) $test_name"
                ((pass_count++))
            else
                echo -e "${RED}[FAIL]${RESET} (negative) $test_name (expected non-zero exit code, got 0)"
                ((fail_count++))
            fi
        else
            # Positive test should pass (exit code 0)
            if [ $exit_code -eq 0 ]; then
                echo -e "${GREEN}[PASS]${RESET} (positive) $test_name"
                ((pass_count++))
            else
                echo -e "${RED}[FAIL]${RESET} (positive) $test_name (exit code: $exit_code)"
                ((fail_count++))
            fi
        fi
    done
}


# Header
echo -e "${BOLD}${BLUE}========================================"
echo -e "       Running Test Suite"
echo -e "========================================${RESET}"

# Check if test directory exists
if [[ ! -d "$TEST_DIR" ]]; then
    echo -e "${RED}Error: Test directory '$TEST_DIR' not found.${RESET}"
    exit 1
fi

# Ensure we are in the correct directory for running cargo
cd "$REPO_ROOT/src/dvt_prover_host" || exit 1

# Run positive tests
if [[ -d "$TEST_DIR/positive" ]]; then
    run_tests_in_dir "$TEST_DIR/positive" "positive"
else
    echo -e "${YELLOW}No 'positive' directory found in $TEST_DIR.${RESET}"
fi

# Run negative tests
if [[ -d "$TEST_DIR/negative" ]]; then
    run_tests_in_dir "$TEST_DIR/negative" "negative"
else
    echo -e "${YELLOW}No 'negative' directory found in $TEST_DIR.${RESET}"
fi

# Summary
echo -e "${BOLD}${BLUE}----------------------------------------${RESET}"
echo -e "${BOLD}Test Summary:${RESET}"
echo -e "  ${GREEN}Passed: $pass_count${RESET}"
echo -e "  ${RED}Failed: $fail_count${RESET}"
echo -e "${BOLD}${BLUE}----------------------------------------${RESET}"

# Exit code
if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${RESET}"
    exit 0
else
    echo -e "${RED}$fail_count test(s) failed.${RESET}"
    exit 1
fi