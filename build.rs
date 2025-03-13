use std::process::Command;

fn main() {
    let commit_output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap_or_else(|_| {
            panic!("Failed to execute git. Make sure 'git' is installed and you're in a git repository.")
        });

    let commit_hash = String::from_utf8(commit_output.stdout)
        .expect("Invalid UTF-8 from git rev-parse HEAD")
        .trim()
        .to_string();

    let status_output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .unwrap_or_else(|_| panic!("Failed to execute git status. Make sure 'git' is installed."));

    let status_str = String::from_utf8_lossy(&status_output.stdout);
    let mut uncommitted_files = Vec::new();

    for line in status_str.lines() {
        if let Some(file) = line.split_whitespace().nth(1) {
            if file.starts_with("crates/") {
                uncommitted_files.push(file.to_string());
            }
        }
    }

    let changed = if uncommitted_files.is_empty() {
        "false"
    } else {
        "true"
    };

    println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit_hash);
    println!("cargo:rustc-env=GIT_UNCOMMITTED={}", changed);

    let uncommitted_files_str = uncommitted_files.join(",");
    println!(
        "cargo:rustc-env=GIT_UNCOMMITTED_FILES={}",
        uncommitted_files_str
    );

    sp1_build::build_program("crates/share_exchange_prove");
    sp1_build::build_program("crates/finalization_prove");
    sp1_build::build_program("crates/bad_parial_key_prove");
    sp1_build::build_program("crates/bad_encrypted_share_prove");
}
