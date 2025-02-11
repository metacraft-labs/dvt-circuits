use clap::{Parser, ValueEnum};
use dvt_abi_host::ProverSerialize;
use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};
use std::env;

use jsonschema::JSONSchema;
use std::error::Error;

pub const SHARE_PROVER_ELF: &[u8] = include_elf!("share_exchange_prove");
pub const FINALE_PROVER_ELF: &[u8] = include_elf!("finalization_prove");
pub const WRONG_FINAL_KEY_GENERATION_PROVER_ELF: &[u8] =
    include_elf!("wrong_final_key_generation_prove");
pub const BAD_ENCRYPTED_SHARE_PROVER_ELF: &[u8] = include_elf!("bad_encrypted_share_prove");

#[derive(Debug, Clone, ValueEnum)]
enum CommandType {
    Finalization,
    Share,
    WrongFinalKeyGeneration,
    BadEcryptedShareProve,
}

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    Execute,
    Prove,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(
        long = "show-report",
        default_value_t = false,
        help = "Show the report after execution."
    )]
    show_report: bool,

    #[arg(long = "input-file", short = 'i', help = "Path to the input file.")]
    input_file: String,

    #[arg(long = "type", value_enum)]
    command_type: CommandType,

    #[arg(
        long = "json-schema-file",
        help = "Path to the JSON validation schema file."
    )]
    json_schema: Option<String>,

    #[arg(
        long = "output-file-path",
        short = 'o',
        help = "Path where the prove will be saved."
    )]
    output_file_path: Option<String>,

    #[arg(long = "mode", value_enum, default_value_t = Mode::Prove, help = "Execution mode (default: Prove).")]
    mode: Mode,
}

fn execute<T>(data: &T, elf: &[u8], show_report: bool)
where
    T: ProverSerialize,
{
    let mut stdin = SP1Stdin::new();
    data.write(&mut stdin);
    let client = ProverClient::new();
    let (_public_values, report) = client
        .execute(elf, stdin)
        .run()
        .unwrap_or_else(|e| panic!("Failed to prove: {}", e));

    if show_report {
        println!("executed: \n {}", report);
    }
}

fn prove<T>(data: &T, elf: &[u8], output_file_path: Option<String>)
where
    T: ProverSerialize,
{
    let mut stdin = SP1Stdin::new();
    data.write(&mut stdin);
    let client = ProverClient::new();

    let (pk, _) = client.setup(elf);

    let proof = client.prove(&pk, stdin).run().unwrap_or_else(|e| {
        panic!("Failed to prove: {}", e);
    });

    match output_file_path {
        Some(path) => {
            proof.save(path).unwrap();
        }
        None => {
            proof.save("proof.bin").unwrap();
        }
    }
}

fn validate_json(schema_path: &str, json_path: &str) -> Result<(), Box<dyn Error>> {
    let schema = dvt_abi::read_text_file(schema_path)?;
    let json = dvt_abi::read_text_file(json_path)?;

    let schema = serde_json::from_str(&schema).unwrap();
    let data = serde_json::from_str(&json).unwrap();

    let compiled_schema = JSONSchema::compile(&schema);

    if compiled_schema.is_err() {
        return Err("invalid schema".into());
    }
    let compiled_schema = compiled_schema.unwrap();

    let ok = compiled_schema.validate(&data);
    if ok.is_err() {
        let errors = ok.unwrap_err();
        for error in errors {
            println!("{}", error);
        }
        return Err("invalid json".into());
    }

    Ok(())
}

fn main() {
    let args = Cli::parse();

    if let Some(path_to_schema) = args.json_schema {
        let ok = validate_json(path_to_schema.as_str(), args.input_file.as_str());
        if ok.is_err() {
            panic!("{}", ok.unwrap_err());
        }
    }

    utils::setup_logger();

    // Depending on the command type, we could do different things here.
    // For now, all variants handle the data similarly.
    match args.command_type {
        CommandType::Share => {
            let data =
                dvt_abi::read_data_from_json_file::<dvt_abi::DvtBlsSharedData>(&args.input_file)
                    .unwrap_or_else(|e| {
                        panic!("Error parsing JSON: {}", e);
                    });

            let abi_data = data.to_abi().unwrap_or_else(|e| {
                panic!("Error converting to ABI data: {}", e);
            });
            match args.mode {
                Mode::Prove => {
                    prove(&abi_data, SHARE_PROVER_ELF, args.output_file_path);
                }
                Mode::Execute => {
                    execute(&abi_data, SHARE_PROVER_ELF, args.show_report);
                }
            }
        }
        CommandType::Finalization => {
            let data =
                dvt_abi::read_data_from_json_file::<dvt_abi::DvtFinalizationData>(&args.input_file)
                    .unwrap_or_else(|e| {
                        panic!("Error parsing JSON: {}", e);
                    });

            let abi_data = data.to_abi().unwrap_or_else(|e| {
                panic!("Error converting to ABI data: {}", e);
            });

            match args.mode {
                Mode::Prove => {
                    prove(&abi_data, FINALE_PROVER_ELF, args.output_file_path);
                }
                Mode::Execute => {
                    execute(&abi_data, FINALE_PROVER_ELF, args.show_report);
                }
            }
        }
        CommandType::WrongFinalKeyGeneration => {
            let data = dvt_abi::read_data_from_json_file::<dvt_abi::DvtWrongFinalKeyGeneration>(
                &args.input_file,
            )
            .unwrap_or_else(|e| {
                panic!("Error parsing JSON: {}", e);
            });

            let abi_data = data.to_abi().unwrap_or_else(|e| {
                panic!("Error converting to ABI data: {}", e);
            });

            match args.mode {
                Mode::Prove => {
                    prove(
                        &abi_data,
                        WRONG_FINAL_KEY_GENERATION_PROVER_ELF,
                        args.output_file_path,
                    );
                }
                Mode::Execute => {
                    execute(
                        &abi_data,
                        WRONG_FINAL_KEY_GENERATION_PROVER_ELF,
                        args.show_report,
                    );
                }
            }
        }
        CommandType::BadEcryptedShareProve => {
            let data = dvt_abi::read_data_from_json_file::<dvt_abi::DvtBadEncryptedShare>(
                &args.input_file,
            )
            .unwrap_or_else(|e| {
                panic!("Error parsing JSON: {}", e);
            });

            let abi_data = data.to_abi().unwrap_or_else(|e| {
                panic!("Error converting to ABI data: {}", e);
            });

            match args.mode {
                Mode::Prove => {
                    prove(
                        &abi_data,
                        BAD_ENCRYPTED_SHARE_PROVER_ELF,
                        args.output_file_path,
                    );
                }
                Mode::Execute => {
                    execute(&abi_data, BAD_ENCRYPTED_SHARE_PROVER_ELF, args.show_report);
                }
            };
        }
    }
}
