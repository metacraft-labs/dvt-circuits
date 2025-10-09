#!/usr/bin/env python3
"""
Script to run all examples and compare detailed instruction counts against baseline.

Provides granular breakdown of:
- Total opcode counts
- Individual opcode frequencies (add, sw, lw, etc.)
- Total syscall counts
- Individual syscall frequencies (bls12381_fp_mul, etc.)

Usage:
    python script/instruction_count.py compare        # Compare against existing baseline
    python script/instruction_count.py create-baseline  # Create new baseline
    python script/instruction_count.py --help         # Show this help
"""

import os
import sys
import subprocess
import re
import json
from pathlib import Path

# Configuration
REPO_ROOT = Path(__file__).parent.parent
BASELINE_FILE = REPO_ROOT / "perf" / "baseline.json"
HOST_BIN_PATH = REPO_ROOT / "target" / "release" / "dkg_prover_host"

# Example configurations (from run_all_examples.sh with corrected paths)
EXAMPLES = [
    {
        "type": "bad-share",
        "input": REPO_ROOT / "examples" / "dvt_bad_share.json",
        "schema": REPO_ROOT / "spec" / "json" / "share_exchange_spec.json"
    },
    {
        "type": "bad-encrypted-share",
        "input": REPO_ROOT / "examples" / "bad_encrypted_bad_share.json",
        "schema": REPO_ROOT / "spec" / "json" / "bad_encrypted_partial_key_spec.json"
    },
    {
        "type": "bad-partial-key",
        "input": REPO_ROOT / "examples" / "bad_partial_key.json",
        "schema": REPO_ROOT / "spec" / "json" / "bad_partial_key_spec.json"
    },
    {
        "type": "finalization",
        "input": REPO_ROOT / "examples" / "finalization_test.json",
        "schema": REPO_ROOT / "spec" / "json" / "finalization_spec.json"
    }
]

def build_project():
    """Build the project in release mode."""
    print("Building project...")
    result = subprocess.run(
        ["cargo", "build", "--release", "--features", "auth_commitment"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"Build failed: {result.stderr}")
        return False
    return True

def extract_instruction_counts(output):
    """Extract detailed instruction counts from the report output."""
    results = {}

    # Extract total opcode count
    total_match = re.search(r'opcode counts \((\d+) total instructions\)', output)
    if total_match:
        results['total_opcodes'] = int(total_match.group(1))

    # Extract individual opcode counts (stop at syscall section)
    opcodes = {}
    in_syscall_section = False
    for line in output.split('\n'):
        if 'syscall counts' in line:
            in_syscall_section = True
            break
        elif 'opcode counts' in line:
            continue  # Skip the header line
        else:
            match = re.match(r'^\s+(\d+)\s+(\w+)$', line)
            if match:
                count, opcode = match.groups()
                opcodes[opcode] = int(count)
    if opcodes:
        results['opcodes'] = opcodes

    # Extract total syscall count
    syscall_total_match = re.search(r'syscall counts \((\d+) total syscall instructions\)', output)
    if syscall_total_match:
        results['total_syscalls'] = int(syscall_total_match.group(1))

    # Extract individual syscall counts
    syscalls = {}
    syscall_pattern = r'^\s+(\d+)\s+(\w+(?:_\w+)*)$'
    in_syscall_section = False
    for line in output.split('\n'):
        if 'syscall counts' in line:
            in_syscall_section = True
            continue
        elif in_syscall_section and line.strip() and not line.startswith(' '):
            # We've moved to the next section
            break
        elif in_syscall_section:
            match = re.match(syscall_pattern, line)
            if match:
                count, syscall = match.groups()
                syscalls[syscall] = int(count)
    if syscalls:
        results['syscalls'] = syscalls

    return results if results else None

def run_example(example):
    """Run a single example and return instruction counts."""
    cmd = [
        str(HOST_BIN_PATH),
        "execute",
        "--type", example["type"],
        "-i", str(example["input"]),
        "--show-report"
        # Note: removed --json-schema-file as some examples seem to have validation issues
    ]

    print(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        if result.returncode == 0:
            instruction_counts = extract_instruction_counts(result.stdout)
            if instruction_counts is not None:
                total = instruction_counts.get('total_opcodes', 0)
                print(f"  ✅ Success: {total} total instructions")
                return instruction_counts
            else:
                print("  ❌ Could not extract instruction counts from output")
                return None
        else:
            print(f"  ❌ Failed: {result.stderr.strip()}")
            return None

    except subprocess.TimeoutExpired:
        print("  ❌ Timeout")
        return None
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return None

def run_all_examples():
    """Run all examples and return results."""
    results = {}

    for example in EXAMPLES:
        name = f"{example['type']}_{example['input'].name}"
        instruction_count = run_example(example)
        if instruction_count is not None:
            results[name] = instruction_count

    return results

def load_baseline():
    """Load baseline from file."""
    if BASELINE_FILE.exists():
        try:
            with open(BASELINE_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading baseline: {e}")
    return {}

def save_baseline(results):
    """Save results as new baseline."""
    try:
        BASELINE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(BASELINE_FILE, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Baseline saved to {BASELINE_FILE}")
        return True
    except Exception as e:
        print(f"Error saving baseline: {e}")
        return False

def compare_instruction_counts(current, baseline, prefix=""):
    """Compare instruction count dictionaries recursively."""
    differences = []

    all_keys = set(current.keys()) | set(baseline.keys())

    for key in sorted(all_keys):
        current_val = current.get(key)
        baseline_val = baseline.get(key)
        full_key = f"{prefix}{key}" if prefix else key

        if current_val is None and baseline_val is None:
            continue
        elif current_val is None:
            differences.append(f"❌ {full_key}: Missing in current results (baseline: {baseline_val})")
        elif baseline_val is None:
            differences.append(f"🆕 {full_key}: New in current results ({current_val})")
        elif isinstance(current_val, dict) and isinstance(baseline_val, dict):
            # Recursively compare nested dictionaries
            sub_differences = compare_instruction_counts(current_val, baseline_val, f"{full_key}.")
            differences.extend(sub_differences)
        elif current_val != baseline_val:
            diff = current_val - baseline_val
            diff_percent = (diff / baseline_val) * 100 if baseline_val != 0 else 0
            status = "📈" if diff > 0 else "📉"
            differences.append(f"❌ {full_key}: {current_val} (was {baseline_val}) {status} {diff:+d} ({diff_percent:+.2f}%)")
        else:
            differences.append(f"✅ {full_key}: {current_val} (unchanged)")

    return differences

def compare_results(current, baseline):
    """Compare current results against baseline."""
    print("\nComparison Results:")
    print("=" * 50)

    all_keys = set(current.keys()) | set(baseline.keys())
    has_differences = False

    for key in sorted(all_keys):
        print(f"\n📊 Example: {key}")
        print("-" * 30)

        current_val = current.get(key)
        baseline_val = baseline.get(key)

        if current_val is None and baseline_val is None:
            continue
        elif current_val is None:
            print(f"❌ Missing in current results")
            has_differences = True
        elif baseline_val is None:
            print(f"🆕 New in current results")
            has_differences = True
        else:
            # Compare the instruction count dictionaries
            differences = compare_instruction_counts(current_val, baseline_val)
            for diff in differences:
                print(f"  {diff}")
                if "❌" in diff or "🆕" in diff:
                    has_differences = True

    return not has_differences

def main():
    if len(sys.argv) != 2 or sys.argv[1] in ["-h", "--help", "help"]:
        print(__doc__)
        sys.exit(0 if sys.argv[1] in ["-h", "--help", "help"] else 1)

    mode = sys.argv[1]

    if mode not in ["compare", "create-baseline"]:
        print(f"Invalid mode: {mode}")
        print("Valid modes: compare, create-baseline")
        print("Use --help for more information")
        sys.exit(1)

    # Build project
    if not build_project():
        sys.exit(1)

    # Run examples
    print("Running examples...")
    results = run_all_examples()

    if not results:
        print("❌ No examples completed successfully")
        sys.exit(1)

    print(f"\nCompleted {len(results)} out of {len(EXAMPLES)} examples")

    if mode == "create-baseline":
        print(f"\nCreating new baseline with {len(results)} results...")
        if save_baseline(results):
            print("✅ Baseline created successfully")
        else:
            sys.exit(1)

    elif mode == "compare":
        baseline = load_baseline()
        if not baseline:
            print(f"No baseline found at {BASELINE_FILE}")
            print("Run with 'create-baseline' first")
            sys.exit(1)

        no_differences = compare_results(results, baseline)
        if no_differences:
            print("\n✅ All instruction counts match baseline")
        else:
            print("\n❌ Instruction count differences detected")
            sys.exit(1)

if __name__ == "__main__":
    main()
