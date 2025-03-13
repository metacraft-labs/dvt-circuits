use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use dvt_abi::{
    read_data_from_json_file, read_text_file, AbiBlsSharedData, AbiFinalizationData,
    DvtBadEncryptedShare, DvtBadPartialShareData, DvtBlsSharedData, DvtFinalizationData, ToAbi,
};
use dvt_abi_host::ProverSerialize;
use jsonschema::JSONSchema;
use serde_json::Value;
use sp1_sdk::{include_elf, proof::SP1ProofWithPublicValues, utils, ProverClient, SP1Stdin};
use std::{error::Error, process};

fn style_error(msg: impl AsRef<str>) -> String {
    format!("❌ {}", msg.as_ref()).red().bold().to_string()
}

fn style_warning(msg: impl AsRef<str>) -> String {
    format!("⚠️ {}", msg.as_ref()).yellow().bold().to_string()
}

fn style_success(msg: impl AsRef<str>) -> String {
    format!("✅ {}", msg.as_ref()).green().bold().to_string()
}

fn style_cyan(msg: impl AsRef<str>) -> String {
    format!("🔎 {}", msg.as_ref()).cyan().bold().to_string()
}

#[derive(Debug, Clone, ValueEnum)]
enum CircuitType {
    Share,
    Finalization,
    BadPartialKey,
    BadEncryptedShare,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Prove {
        #[arg(long = "input-file", short = 'i')]
        input_file: String,
        #[arg(long = "type", value_enum)]
        subtype: CircuitType,
        #[arg(long = "output-file-path", short = 'o')]
        output_file_path: Option<String>,
        #[arg(long = "json-schema-file")]
        json_schema: Option<String>,
    },
    Execute {
        #[arg(long = "input-file", short = 'i')]
        input_file: String,
        #[arg(long = "type", value_enum)]
        subtype: CircuitType,
        #[arg(long = "json-schema-file")]
        json_schema: Option<String>,
        #[arg(long = "show-report", default_value_t = false)]
        show_report: bool,
    },
    ValidateSchema {
        #[arg(long = "schema-file", short = 's')]
        schema_file: String,
        #[arg(long = "json-file", short = 'j')]
        json_file: String,
    },
    Verify {
        #[arg(long = "input-file", short = 'i')]
        proof_file: String,
        #[arg(long = "type", value_enum)]
        subtype: CircuitType,
        #[arg(long = "show-report", default_value_t = false)]
        show_report: bool,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

pub const SHARE_PROVER_ELF: &[u8] = include_elf!("share_exchange_prove");
pub const FINALE_PROVER_ELF: &[u8] = include_elf!("finalization_prove");
pub const BAD_PARTIAL_KEY_PROVER_ELF: &[u8] = include_elf!("bad_parial_key_prove");
pub const BAD_ENCRYPTED_SHARE_PROVER_ELF: &[u8] = include_elf!("bad_encrypted_share_prove");

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    utils::setup_logger();

    match cli.command {
        Commands::Prove {
            input_file,
            subtype,
            output_file_path,
            json_schema,
        } => {
            validate_if_needed(json_schema.as_deref(), &input_file)?;

            match subtype {
                CircuitType::Share => {
                    let dvt_data = read_data_from_json_file::<DvtBlsSharedData>(&input_file)
                        .map_err(|e| style_error(format!("Failed to read share data: {e}")))?;
                    let abi_data: AbiBlsSharedData = dvt_data
                        .to_abi()
                        .map_err(|e| style_error(format!("Share data to ABI failed: {e}")))?;
                    prove(
                        &abi_data,
                        SHARE_PROVER_ELF,
                        &input_file,
                        output_file_path.as_deref(),
                    )?;
                }
                CircuitType::Finalization => {
                    let dvt_data = read_data_from_json_file::<DvtFinalizationData>(&input_file)
                        .map_err(|e| {
                            style_error(format!("Failed to read finalization data: {e}"))
                        })?;
                    let abi_data: AbiFinalizationData = dvt_data.to_abi().map_err(|e| {
                        style_error(format!("Finalization data to ABI failed: {e}"))
                    })?;
                    prove(
                        &abi_data,
                        FINALE_PROVER_ELF,
                        &input_file,
                        output_file_path.as_deref(),
                    )?;
                }
                CircuitType::BadPartialKey => {
                    let dvt_data = read_data_from_json_file::<DvtBadPartialShareData>(&input_file)
                        .map_err(|e| {
                            style_error(format!("Failed to read bad partial key data: {e}"))
                        })?;
                    let abi_data = dvt_data.to_abi().map_err(|e| {
                        style_error(format!("Bad partial key data to ABI failed: {e}"))
                    })?;
                    prove(
                        &abi_data,
                        BAD_PARTIAL_KEY_PROVER_ELF,
                        &input_file,
                        output_file_path.as_deref(),
                    )?;
                }
                CircuitType::BadEncryptedShare => {
                    let dvt_data = read_data_from_json_file::<DvtBadEncryptedShare>(&input_file)
                        .map_err(|e| {
                            style_error(format!("Failed to read bad encrypted share data: {e}"))
                        })?;
                    let abi_data = dvt_data.to_abi().map_err(|e| {
                        style_error(format!("Bad encrypted share data to ABI failed: {e}"))
                    })?;
                    prove(
                        &abi_data,
                        BAD_ENCRYPTED_SHARE_PROVER_ELF,
                        &input_file,
                        output_file_path.as_deref(),
                    )?;
                }
            }
        }
        Commands::Execute {
            input_file,
            subtype,
            json_schema,
            show_report,
        } => {
            validate_if_needed(json_schema.as_deref(), &input_file)?;

            match subtype {
                CircuitType::Share => {
                    let dvt_data = read_data_from_json_file::<DvtBlsSharedData>(&input_file)
                        .map_err(|e| style_error(format!("Failed to read share data: {e}")))?;
                    let abi_data: AbiBlsSharedData = dvt_data
                        .to_abi()
                        .map_err(|e| style_error(format!("Share data to ABI failed: {e}")))?;
                    execute(&abi_data, SHARE_PROVER_ELF, show_report)?;
                }
                CircuitType::Finalization => {
                    let dvt_data = read_data_from_json_file::<DvtFinalizationData>(&input_file)
                        .map_err(|e| {
                            style_error(format!("Failed to read finalization data: {e}"))
                        })?;
                    let abi_data: AbiFinalizationData = dvt_data.to_abi().map_err(|e| {
                        style_error(format!("Finalization data to ABI failed: {e}"))
                    })?;
                    execute(&abi_data, FINALE_PROVER_ELF, show_report)?;
                }
                CircuitType::BadPartialKey => {
                    let dvt_data = read_data_from_json_file::<DvtBadPartialShareData>(&input_file)
                        .map_err(|e| {
                            style_error(format!("Failed to read bad partial key data: {e}"))
                        })?;
                    let abi_data = dvt_data.to_abi().map_err(|e| {
                        style_error(format!("Bad partial key data to ABI failed: {e}"))
                    })?;
                    execute(&abi_data, BAD_PARTIAL_KEY_PROVER_ELF, show_report)?;
                }
                CircuitType::BadEncryptedShare => {
                    let dvt_data = read_data_from_json_file::<DvtBadEncryptedShare>(&input_file)
                        .map_err(|e| {
                            style_error(format!("Failed to read bad encrypted share data: {e}"))
                        })?;
                    let abi_data = dvt_data.to_abi().map_err(|e| {
                        style_error(format!("Bad encrypted share data to ABI failed: {e}"))
                    })?;
                    execute(&abi_data, BAD_ENCRYPTED_SHARE_PROVER_ELF, show_report)?;
                }
            }
        }
        Commands::ValidateSchema {
            schema_file,
            json_file,
        } => {
            if let Err(e) = validate_json(&schema_file, &json_file) {
                return Err(style_error(format!("Schema validation error: {e}")).into());
            } else {
                println!(
                    "{}",
                    style_success("Validation successful. No errors found.")
                );
            }
        }
        Commands::Verify {
            proof_file,
            subtype,
            show_report,
        } => match subtype {
            CircuitType::Share => {
                verify_proof(SHARE_PROVER_ELF, &proof_file, show_report)?;
            }
            CircuitType::Finalization => {
                verify_proof(FINALE_PROVER_ELF, &proof_file, show_report)?;
            }
            CircuitType::BadPartialKey => {
                verify_proof(BAD_PARTIAL_KEY_PROVER_ELF, &proof_file, show_report)?;
            }
            CircuitType::BadEncryptedShare => {
                verify_proof(BAD_ENCRYPTED_SHARE_PROVER_ELF, &proof_file, show_report)?;
            }
        },
    }

    Ok(())
}

fn main() {
    let commit_hash = env!("GIT_COMMIT_HASH");
    let uncommitted = env!("GIT_UNCOMMITTED");
    let uncommitted_files = env!("GIT_UNCOMMITTED_FILES");

    println!("🔗 Commit Hash: {}", commit_hash);

    if uncommitted == "true" {
        println!("{}", style_warning("WARNING:Uncommitted Changes"));
        if !uncommitted_files.is_empty() {
            println!("📂 Uncommitted Files in ./create:");
            for file in uncommitted_files.split(',') {
                println!("  📄 {}", file);
            }
        }
    }
    let cli = Cli::parse();
    match run(cli) {
        Ok(_) => {}
        Err(e) => {
            println!("{e}");
            process::exit(1);
        }
    }
}

fn execute<T>(data: &T, elf: &[u8], show_report: bool) -> Result<(), Box<dyn Error>>
where
    T: ProverSerialize,
{
    let mut stdin = SP1Stdin::new();
    data.write(&mut stdin);
    let client = ProverClient::new();
    let (_public_values, report) = client
        .execute(elf, stdin)
        .run()
        .map_err(|e| style_error(format!("Verification failed: {e}")))?;
    if show_report {
        println!("{}\n{}", style_cyan("Verification report:"), report);
    }
    Ok(())
}

fn prove<T>(
    data: &T,
    elf: &[u8],
    input_file: &str,
    output_file_path: Option<&str>,
) -> Result<(), Box<dyn Error>>
where
    T: ProverSerialize,
{
    let mut stdin = SP1Stdin::new();
    data.write(&mut stdin);
    let client = ProverClient::new();
    let (pk, _) = client.setup(elf);
    let proof = client
        .prove(&pk, stdin)
        .run()
        .map_err(|e| style_error(format!("Proof generation failed: {e}")))?;

    let path = output_file_path
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}_proof.bin", input_file));

    proof
        .save(&path)
        .map_err(|e| style_error(format!("Saving proof failed: {e}")))?;

    println!("{} {}", style_success("Proof saved to:"), path);
    Ok(())
}

fn verify_proof(elf: &[u8], proof_file: &str, show_report: bool) -> Result<(), Box<dyn Error>> {
    let client = ProverClient::new();
    let (_, vk) = client.setup(elf);

    let proof_with_pub_values = SP1ProofWithPublicValues::load(proof_file).map_err(|e| {
        style_error(format!(
            "Failed to load proof form {} with error: {e}",
            proof_file
        ))
    })?;
    let proof = proof_with_pub_values.bytes();
    let public_values = proof_with_pub_values.public_values.to_vec();

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(proof);
    stdin.write_vec(public_values);
    stdin.write(&vk);

    let (_, report) = client
        .execute(elf, stdin)
        .run()
        .map_err(|e| style_error(format!("Verification failed: {e}")))?;

    if show_report {
        println!("{}", report);
    }
    Ok(())
}

fn validate_if_needed(schema_path: Option<&str>, json_path: &str) -> Result<(), Box<dyn Error>> {
    if let Some(path) = schema_path {
        validate_json(path, json_path)?;
    }
    Ok(())
}

fn validate_json(schema_path: &str, json_path: &str) -> Result<(), Box<dyn Error>> {
    let schema_str = read_text_file(schema_path)
        .map_err(|e| style_error(format!("Could not read schema file '{schema_path}': {e}")))?;
    let json_str = read_text_file(json_path)
        .map_err(|e| style_error(format!("Could not read JSON file '{json_path}': {e}")))?;

    let schema: Value = serde_json::from_str(&schema_str)
        .map_err(|e| style_error(format!("Invalid JSON schema in '{schema_path}': {e}")))?;
    let data: Value = serde_json::from_str(&json_str)
        .map_err(|e| style_error(format!("Invalid JSON data in '{json_path}': {e}")))?;

    let compiled_schema = JSONSchema::compile(&schema)
        .map_err(|e| style_error(format!("Failed to compile the JSON schema: {e}")))?;

    if let Err(validation_errors) = compiled_schema.validate(&data) {
        for error in validation_errors {
            eprintln!(
                "{} {error}",
                style_error(format!("Validation error in '{json_path}':"))
            );
        }
        return Err(style_error(format!("JSON validation failed for '{json_path}'")).into());
    }

    Ok(())
}
