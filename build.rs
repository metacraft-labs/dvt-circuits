use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    let commit_hash = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let uncommitted_output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "".to_string());

    let uncommitted_files: Vec<String> = uncommitted_output
        .lines()
        .filter_map(|line| {
            let file_path = line[3..].to_string(); // Remove git status prefixes (e.g., " M filename.txt")
            if file_path.starts_with("crates/") {
                Some(file_path)
            } else {
                None
            }
        })
        .collect();

    let uncommitted_flag = !uncommitted_files.is_empty();

    let uncommitted_files_array = uncommitted_files
        .iter()
        .map(|file| format!(r#""{}""#, file))
        .map(|line| format!("    {},\n", line))
        .collect::<Vec<String>>()
        .join("");

    let git_info_content = format!(
        r#"#[rustfmt::skip]
mod git_info_contents {{
    pub const COMMIT_HASH: &str = "{commit_hash}";
    pub const UNCOMMITTED_CHANGES: bool = {uncommitted_flag};
    pub const UNCOMMITTED_FILES: &[&str] = &[
        {uncommitted_files_array}
    ];
}}
pub use git_info_contents::*;
"#
    );

    let dest_path = Path::new("./src/git_info.rs");

    fs::write(dest_path, git_info_content).expect("Failed to write git_info.rs");

    sp1_build::build_program("crates/bad_share_exchange_prove");
    sp1_build::build_program("crates/finalization_prove");
    sp1_build::build_program("crates/bad_parial_key_prove");
    sp1_build::build_program("crates/bad_encrypted_share_prove");
}
