use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};
pub const SHARE_PROVER_ELF: &[u8] = include_elf!("share_exchange_prove");
pub const FINALE_PROVER_ELF: &[u8] = include_elf!("finalization_prove");
pub const WRONG_FINAL_KEY_GENERATION_ELF: &[u8] = include_elf!("wrong_final_key_generation_prove");

use clap::{Parser, ValueEnum};
use dvt_abi;
use dvt_abi_host::ProverSerialize;
use std::env;

use jsonschema::JSONSchema;
use std::error::Error;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Clone, ValueEnum)]
enum CommandType {
    Finalization,
    Share,
    WrongFinalKeyGeneration,
}

#[derive(Debug, Clone, ValueEnum)]
enum Mode {
    Execute,
    Prove
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long = "show-report", default_value_t = false)]
    show_report: bool,

    #[arg(long = "input-file")]
    input_file: String,

    #[arg(long = "type", value_enum)]
    command_type: CommandType,

    #[arg(long = "json-schema-file")]
    json_schema: Option<String>,

    #[arg(long = "mode", value_enum, default_value_t = Mode::Prove)]
    mode: Mode,
}

fn read_text_file(filename: &str) -> Result<String, Box<dyn Error>> {
    let mut file = File::open(filename).map_err(|e| format!("Error opening file: {}", e))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| format!("Error reading file: {}", e))?;
    Ok(contents)
}

fn execute<T>(data: &T, elf: &[u8], show_report: bool) where T: ProverSerialize {

    print!("executing....");
    let mut stdin = SP1Stdin::new();
    data.write(&mut stdin);
    let client = ProverClient::new();
    let (_public_values, report) = client
        .execute(elf, stdin)
        .run()
        .unwrap_or_else(|e| {
            eprintln!("Failed to prove: {}", e);
            std::process::exit(1);
        });
    
    print!("executed");
    if show_report {
        println!("executed: {}", report);
    }
}

fn prove<T>(data: &T, elf: &[u8]) where T: ProverSerialize {
    let mut stdin = SP1Stdin::new();
    data.write(&mut stdin);
    let client = ProverClient::new();

    let (pk, vk) = client.setup(elf);

    print!("proving....");
    let proof = client
        .prove(&pk, stdin)
        .run()
        .unwrap_or_else(|e| {
            eprintln!("Failed to prove: {}", e);
            std::process::exit(1);
        });
    
    print!("saving file");
    proof.save("proof.bin").unwrap();
    print!("file was saved")
}

fn validate_json(schema_path: &str, json_path: &str) -> Result<(), Box<dyn Error>> {
    let schema = read_text_file(schema_path)?;
    let json = read_text_file(json_path)?;

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

    if args.input_file.is_empty() {
        eprintln!("No file name provided after '--input-file'.");
        std::process::exit(1);
    }

    if args.json_schema.is_some() {
        let ok = validate_json(args.json_schema.unwrap().as_str(), args.input_file.as_str());
        if ok.is_err() {
            eprintln!("{}", ok.unwrap_err());
            std::process::exit(1);
        }
    }

    utils::setup_logger();

    // Depending on the command type, we could do different things here.
    // For now, both variants handle the data similarly.
    match args.command_type {
        CommandType::Share => {
            let data =
                dvt_abi::read_data_from_json_file::<dvt_abi::DvtBlsSharedData>(&args.input_file)
                    .unwrap_or_else(|e| {
                        eprintln!("Error parsing JSON: {}", e);
                        std::process::exit(1);
                    });

            let abi_data = data.to_abi().unwrap_or_else(|e| {
                eprintln!("Error converting to ABI data: {}", e);
                std::process::exit(1);
            });
            match args.mode {
                Mode::Prove => {
                    prove(&abi_data, SHARE_PROVER_ELF);
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
                        eprintln!("Error parsing JSON: {}", e);
                        std::process::exit(1);
                    });

            let abi_data = data.to_abi().unwrap_or_else(|e| {
                eprintln!("Error converting to ABI data: {}", e);
                std::process::exit(1);
            });

            match args.mode {
                Mode::Prove => {
                    prove(&abi_data, FINALE_PROVER_ELF);
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
                eprintln!("Error parsing JSON: {}", e);
                std::process::exit(1);
            });

            let abi_data = data.to_abi().unwrap_or_else(|e| {
                eprintln!("Error converting to ABI data: {}", e);
                std::process::exit(1);
            });

            match args.mode {
                Mode::Prove => {
                    prove(&abi_data, WRONG_FINAL_KEY_GENERATION_ELF);
                }
                Mode::Execute => {
                    execute(&abi_data, WRONG_FINAL_KEY_GENERATION_ELF, args.show_report);
                }
            }
        }
    };
}
