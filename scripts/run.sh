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

pass_count=0
fail_count=0
skip_count=0
disabled_count=0
execution_count=0
total_pass_count=0
total_fail_count=0
total_skip_count=0
total_disabled_count=0

# Parse arguments
FILTER=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --filter)
            FILTER=$2
            shift 2
            ;;
        *)
            echo -e "${RED}Unknown option: $1${RESET}"
            exit 1
            ;;
    esac
done

run_tests_in_dir() {
    local dir=$1

    # Find all JSON test files in the directory
    local test_files=($(find "$dir" -type f -name "*.json"))
    if [ ${#test_files[@]} -eq 0 ]; then
        echo -e "${YELLOW}No JSON test files found in $dir.${RESET}"
        return
    fi

    skipped_tests=()

    for test_file in "${test_files[@]}"; do
        # Apply the filter if provided
        if [[ -n "$FILTER" && ! $(basename "$test_file") =~ $FILTER ]]; then
            skipped_tests+=("$test_file")  
            ((skip_count++))
            continue
        fi

        test_name=$(basename "$test_file")

        cmd_args=$(jq -r '.params.cmd_extra_args' "$test_file")
        expected_exit_code=$(jq -r '.params.expected_exit_code' "$test_file")
        scenario=$(jq -r '.scenario' "$test_file")
        disabled=$(jq -r '.params.disabled' "$test_file")

        if [[ $disabled == "true" ]]; then
            skipped_tests+=("$test_file")
            ((disabled_count++))
            continue
        fi

        echo $scenario > scenario.json
        target/release/dvt_prover_host --input-file scenario.json $cmd_args
        exit_code=$?

        ((execution_count++))
        if [ $exit_code -eq $expected_exit_code ]; then
            echo -e "${GREEN}[PASS]${RESET}${BOLD} $test_file${RESET}"
            ((pass_count++))
        else
            echo -e "${RED}[FAIL]${RESET}${BOLD} $test_file (expected exit code: $expected_exit_code, got $exit_code) ${RESET}"
            ((fail_count++))
        fi

        rm scenario.json
    done

    if [[ ${#skipped_tests[@]} -gt 0 ]]; then
        echo -e "\n${YELLOW}Skipped tests:${RESET}"
        for skipped_test in "${skipped_tests[@]}"; do
            echo "- $skipped_test"
        done
    fi
}

cargo  build --release
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo -e "${RED}Error: Cargo build failed.${RESET}"
    exit 1
fi

# Header
echo -e "${BOLD}${BLUE}========================================"
echo -e "       Running Test Suites"
echo -e "========================================${RESET}"

if [[ ! -d "$TEST_DIR" ]]; then
    echo -e "${RED}Error: Test directory '$TEST_DIR' not found.${RESET}"
    exit 1
fi

for SUITE in "$TEST_DIR"/*/; do
    if [[ -d "$SUITE" ]]; then
        run_tests_in_dir "$SUITE"

        if [ $execution_count -gt 0 ]; then
            echo -e "${BOLD}${BLUE}----------------------------------------${RESET}"
            echo -e "${BOLD} $SUITE Summary:${RESET}"
            echo -e "  ${GREEN}Passed: $pass_count${RESET}"
            echo -e "  ${RED}Failed: $fail_count${RESET}"
            if [ $disabled_count -gt 0 ]; then
                echo -e "  ${BLUE}Disabled: $disabled_count${RESET}"
            fi
            if [ $skip_count -gt 0 ]; then
                echo -e "  ${YELLOW}Skipped: $skip_count${RESET}"
            fi
            echo -e "${BOLD}${BLUE}----------------------------------------${RESET}"
        fi

        total_pass_count=$((total_pass_count + pass_count))
        total_fail_count=$((total_fail_count + fail_count))
        total_disabled_count=$((total_disabled_count + disabled_count))
        total_skip_count=$((total_skip_count + skip_count))
        pass_count=0
        fail_count=0
        disabled_count=0
        skip_count=0
        execution_count=0
    fi
done

echo -e "${BOLD}${BLUE}----------------------------------------${RESET}"
echo -e "${BOLD}Test Summary:${RESET}"
echo -e "  ${GREEN}Passed: $total_pass_count${RESET}"

echo -e "  ${RED}Failed: $total_fail_count${RESET}"
if [ $total_disabled_count -gt 0 ]; then
    echo -e "  ${BLUE}Disabled: $total_disabled_count${RESET}"
fi
if [ $total_skip_count -gt 0 ]; then
    echo -e "  ${YELLOW}Skipped: $total_skip_count${RESET}"
fi
echo -e "${BOLD}${BLUE}----------------------------------------${RESET}"

if [ $total_fail_count -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${RESET}"
else
    echo -e "${RED}$total_fail_count test(s) failed.${RESET}"
fi
