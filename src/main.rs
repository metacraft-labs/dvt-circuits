use clap::{Parser, Subcommand, ValueEnum};
use colored::*;
use dkg::{
    BadEncryptedShare, BadPartialShareData, BlsDkgWithSecp256kCommitment, DkgSetup, DkgSetupTypes,
    FinalizationData, SharedData,
};
use jsonschema::JSONSchema;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sp1_sdk::{include_elf, proof::SP1ProofWithPublicValues, utils, ProverClient, SP1Stdin};
use std::{error::Error, fs::File, io::Write, process};
pub mod file_utils;
pub mod git_info;
pub mod service;
use service::node::HttpService;

use file_utils::*;

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
    BadShare,
    Finalization,
    BadPartialKey,
    BadEncryptedShare,
}

impl TryFrom<&str> for CircuitType {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        CircuitType::from_str(value, false) // case-sensitive; pass true for case-insensitive
    }
}

#[derive(Debug, Clone, ValueEnum)]
enum SchemaType {
    Json,
    Yaml,
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
    GetSchema {
        #[arg(long = "type", value_enum)]
        subtype: CircuitType,
        #[arg(long = "schema-type", value_enum)]
        schema_type: SchemaType,
        #[arg(long = "output-file-path", short = 'o')]
        output_file_path: Option<String>,
    },
    Verify {
        #[arg(long = "input-file", short = 'i')]
        proof_file: String,
        #[arg(long = "type", value_enum)]
        subtype: CircuitType,
        #[arg(long = "show-report", default_value_t = false)]
        show_report: bool,
    },
    Node {
        #[arg(long = "port", short = 'a')]
        port: u16,
    },
}

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

pub const SHARE_PROVER_ELF: &[u8] = include_elf!("bad_share_exchange_prove");
pub const FINALE_PROVER_ELF: &[u8] = include_elf!("finalization_prove");
pub const BAD_PARTIAL_KEY_PROVER_ELF: &[u8] = include_elf!("bad_parial_key_prove");
pub const BAD_ENCRYPTED_SHARE_PROVER_ELF: &[u8] = include_elf!("bad_encrypted_share_prove");

fn schema_for<T>(t: SchemaType) -> String
where
    T: JsonSchema,
{
    match t {
        SchemaType::Json => dkg::types::json_schema_for_type::<T>(),
        SchemaType::Yaml => dkg::types::yaml_schema_for_type::<T>(),
    }
}

fn on_prove<Setup>(typ: String, data: Value) -> Result<Value, service::node::DynErr>
where
    Setup: DkgSetup + DkgSetupTypes<Setup> + for<'a> Deserialize<'a> + Serialize,
    SharedData<Setup>: JsonSchema,
    FinalizationData<Setup>: JsonSchema,
    BadPartialShareData<Setup>: JsonSchema,
    BadEncryptedShare<Setup>: JsonSchema,
{
    match CircuitType::try_from(typ.as_str())? {
        CircuitType::BadShare => {
            let d: SharedData<Setup> = serde_json::from_value(data)?;
            prove(&d, SHARE_PROVER_ELF, "", None).map_err(|e| e.to_string())?;
        }
        CircuitType::Finalization => {
            let d: FinalizationData<Setup> = serde_json::from_value(data)?;
            prove(&d, FINALE_PROVER_ELF, "", None).map_err(|e| e.to_string())?;
        }
        CircuitType::BadPartialKey => {
            let d: BadPartialShareData<Setup> = serde_json::from_value(data)?;
            prove(&d, BAD_PARTIAL_KEY_PROVER_ELF, "", None).map_err(|e| e.to_string())?;
        }
        CircuitType::BadEncryptedShare => {
            let d: BadEncryptedShare<Setup> = serde_json::from_value(data)?;
            prove(&d, BAD_ENCRYPTED_SHARE_PROVER_ELF, "", None).map_err(|e| e.to_string())?;
        }
    }
    Ok(serde_json::json!({ "status": "proved" }))
}

fn on_execute<Setup>(typ: String, data: Value) -> Result<Value, service::node::DynErr>
where
    Setup: DkgSetup + DkgSetupTypes<Setup> + for<'a> Deserialize<'a> + Serialize,
    SharedData<Setup>: JsonSchema,
    FinalizationData<Setup>: JsonSchema,
    BadPartialShareData<Setup>: JsonSchema,
    BadEncryptedShare<Setup>: JsonSchema,
{
    match CircuitType::try_from(typ.as_str())? {
        CircuitType::BadShare => {
            let d: SharedData<Setup> = serde_json::from_value(data)?;
            execute(&d, SHARE_PROVER_ELF, false).map_err(|e| e.to_string())?;
        }
        CircuitType::Finalization => {
            let d: FinalizationData<Setup> = serde_json::from_value(data)?;
            execute(&d, FINALE_PROVER_ELF, false).map_err(|e| e.to_string())?;
        }
        CircuitType::BadPartialKey => {
            let d: BadPartialShareData<Setup> = serde_json::from_value(data)?;
            execute(&d, BAD_PARTIAL_KEY_PROVER_ELF, false).map_err(|e| e.to_string())?;
        }
        CircuitType::BadEncryptedShare => {
            let d: BadEncryptedShare<Setup> = serde_json::from_value(data)?;
            execute(&d, BAD_ENCRYPTED_SHARE_PROVER_ELF, false).map_err(|e| e.to_string())?;
        }
    }
    Ok(serde_json::json!({ "status": "executed" }))
}

fn on_get_spec<Setup>(typ: String) -> Result<Value, service::node::DynErr>
where
    Setup: DkgSetup + DkgSetupTypes<Setup> + for<'a> Deserialize<'a> + Serialize,
    SharedData<Setup>: JsonSchema,
    FinalizationData<Setup>: JsonSchema,
    BadPartialShareData<Setup>: JsonSchema,
    BadEncryptedShare<Setup>: JsonSchema,
{
    let schema_str = match CircuitType::try_from(typ.as_str())? {
        CircuitType::BadShare => dkg::types::json_schema_for_type::<SharedData<Setup>>(),
        CircuitType::Finalization => dkg::types::json_schema_for_type::<FinalizationData<Setup>>(),
        CircuitType::BadPartialKey => {
            dkg::types::json_schema_for_type::<BadPartialShareData<Setup>>()
        }
        CircuitType::BadEncryptedShare => {
            dkg::types::json_schema_for_type::<BadEncryptedShare<Setup>>()
        }
    };

    let lol = serde_json::from_str::<serde_json::Value>(&schema_str)
        .map_err(|e| style_error(format!("invalid schema json: {e}")))?;
    Ok(serde_json::json!({ "status": "ok", "schema":  lol}))
}

fn run<Setup>(cli: Cli) -> Result<(), Box<dyn Error>>
where
    Setup: DkgSetup + DkgSetupTypes<Setup> + for<'a> Deserialize<'a> + Serialize,
    SharedData<Setup>: JsonSchema,
    FinalizationData<Setup>: JsonSchema,
    BadPartialShareData<Setup>: JsonSchema,
    BadEncryptedShare<Setup>: JsonSchema,
{
    utils::setup_logger();

    match cli.command {
        Commands::Node { port } => {
            let server = HttpService::new(
                ([127, 0, 0, 1], port).into(),
                |typ, data| on_prove::<Setup>(typ, data),
                |typ, data| on_execute::<Setup>(typ, data),
                |typ| on_get_spec::<Setup>(typ),
            );
            let rt = tokio::runtime::Runtime::new()
                .map_err(|e| style_error(format!("failed to start Tokio runtime: {e}")))?;

            rt.block_on(async {
                if let Err(e) = server.run().await {
                    eprintln!("server error: {e}");
                }
            });
        }
        Commands::Prove {
            input_file,
            subtype,
            output_file_path,
            json_schema,
        } => {
            validate_if_needed(json_schema.as_deref(), &input_file)?;

            match subtype {
                CircuitType::BadShare => {
                    let dkg_data = read_data_from_json_file::<SharedData<Setup>>(&input_file)
                        .map_err(|e| style_error(format!("Failed to read share data: {e}")))?;
                    prove(
                        &dkg_data,
                        SHARE_PROVER_ELF,
                        &input_file,
                        output_file_path.as_deref(),
                    )?;
                }
                CircuitType::Finalization => {
                    let dkg_data = read_data_from_json_file::<FinalizationData<Setup>>(&input_file)
                        .map_err(|e| {
                            style_error(format!("Failed to read finalization data: {e}"))
                        })?;
                    prove(
                        &dkg_data,
                        FINALE_PROVER_ELF,
                        &input_file,
                        output_file_path.as_deref(),
                    )?;
                }
                CircuitType::BadPartialKey => {
                    let dkg_data =
                        read_data_from_json_file::<BadPartialShareData<Setup>>(&input_file)
                            .map_err(|e| {
                                style_error(format!("Failed to read bad partial key data: {e}"))
                            })?;
                    prove(
                        &dkg_data,
                        BAD_PARTIAL_KEY_PROVER_ELF,
                        &input_file,
                        output_file_path.as_deref(),
                    )?;
                }
                CircuitType::BadEncryptedShare => {
                    let dkg_data = read_data_from_json_file::<BadEncryptedShare<Setup>>(
                        &input_file,
                    )
                    .map_err(|e| {
                        style_error(format!("Failed to read bad encrypted share data: {e}"))
                    })?;
                    prove(
                        &dkg_data,
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
                CircuitType::BadShare => {
                    let dkg_data = read_data_from_json_file::<SharedData<Setup>>(&input_file)
                        .map_err(|e| style_error(format!("Failed to read share data: {e}")))?;
                    execute(&dkg_data, SHARE_PROVER_ELF, show_report)?;
                }
                CircuitType::Finalization => {
                    let dkg_data = read_data_from_json_file::<FinalizationData<Setup>>(&input_file)
                        .map_err(|e| {
                            style_error(format!("Failed to read finalization data: {e}"))
                        })?;
                    execute(&dkg_data, FINALE_PROVER_ELF, show_report)?;
                }
                CircuitType::BadPartialKey => {
                    let dkg_data =
                        read_data_from_json_file::<BadPartialShareData<Setup>>(&input_file)
                            .map_err(|e| {
                                style_error(format!("Failed to read bad partial key data: {e}"))
                            })?;
                    execute(&dkg_data, BAD_PARTIAL_KEY_PROVER_ELF, show_report)?;
                }
                CircuitType::BadEncryptedShare => {
                    let dkg_data = read_data_from_json_file::<BadEncryptedShare<Setup>>(
                        &input_file,
                    )
                    .map_err(|e| {
                        style_error(format!("Failed to read bad encrypted share data: {e}"))
                    })?;
                    execute(&dkg_data, BAD_ENCRYPTED_SHARE_PROVER_ELF, show_report)?;
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
            CircuitType::BadShare => {
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

        Commands::GetSchema {
            subtype,
            schema_type: shema_type,
            output_file_path,
        } => {
            let schema_str = match subtype {
                CircuitType::BadShare => schema_for::<SharedData<Setup>>(shema_type),
                CircuitType::Finalization => schema_for::<FinalizationData<Setup>>(shema_type),
                CircuitType::BadPartialKey => schema_for::<BadPartialShareData<Setup>>(shema_type),
                CircuitType::BadEncryptedShare => {
                    schema_for::<BadEncryptedShare<Setup>>(shema_type)
                }
            };
            match output_file_path {
                Some(path) => {
                    let mut file = File::create(path)
                        .map_err(|e| style_error(format!("Failed to create output file: {e}")))?;
                    file.write_all(schema_str.as_bytes())
                        .map_err(|e| style_error(format!("Failed to write to output file: {e}")))?;
                }
                None => println!("{}", schema_str),
            }
        }
    }

    Ok(())
}

fn main() {
    let commit_hash = git_info::COMMIT_HASH;
    let uncommitted = git_info::UNCOMMITTED_CHANGES;
    let uncommitted_files = git_info::UNCOMMITTED_FILES;

    println!("🔗 Commit Hash: {}", commit_hash);

    if uncommitted {
        println!("{}", style_warning("WARNING:Uncommitted Changes"));
        println!("📂 Uncommitted Files in ./create:");
        for file in uncommitted_files {
            println!("  📄 {}", file);
        }
    }
    let cli = Cli::parse();
    match run::<BlsDkgWithSecp256kCommitment>(cli) {
        Ok(_) => {}
        Err(e) => {
            println!("{e}");
            process::exit(1);
        }
    }
}

fn execute<T>(data: &T, elf: &[u8], show_report: bool) -> Result<(), Box<dyn Error>>
where
    T: serde::ser::Serialize,
{
    let mut stdin = SP1Stdin::new();
    let bin = serde_cbor::to_vec(data).expect("Failed to serialize data");
    println!("input len: {}", bin.len());
    stdin.write(&bin);
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
    T: serde::ser::Serialize,
{
    let mut stdin = SP1Stdin::new();
    let bin = serde_cbor::to_vec(data).expect("Failed to serialize data");
    stdin.write(&bin);
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
