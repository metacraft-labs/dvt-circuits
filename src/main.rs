use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};
pub const SHARE_PROVER_ELF: &[u8] = include_elf!("share_exchange_prove");
pub const FINALE_PROVER_ELF: &[u8] = include_elf!("finalization_prove");

use clap::{Parser, ValueEnum};
use dvt_abi;
use dvt_abi_host::ProverSerialize;
use std::env;

#[derive(Debug, Clone, ValueEnum)]
enum CommandType {
    Finalization,
    Share,
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
}

fn main() {
    let args = Cli::parse();

    if args.input_file.is_empty() {
        eprintln!("No file name provided after '--input-file'.");
        std::process::exit(1);
    }

    utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    // Depending on the command type, we could do different things here.
    // For now, both variants handle the data similarly.
    let report = match args.command_type {
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

            abi_data.write(&mut stdin);
            let client = ProverClient::new();
            let (_public_values, report) = client
                .execute(SHARE_PROVER_ELF, stdin)
                .run()
                .unwrap_or_else(|e| {
                    eprintln!("Failed to prove: {}", e);
                    std::process::exit(1);
                });
            report
        }
        CommandType::Finalization => {
            print!("finalization\n");

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

            abi_data.write(&mut stdin);
            let client = ProverClient::new();
            let (_public_values, report) = client
                .execute(FINALE_PROVER_ELF, stdin)
                .run()
                .unwrap_or_else(|e| {
                    eprintln!("Failed to prove: {}", e);
                    std::process::exit(1);
                });
            report
        }
    };

    if args.show_report {
        println!("report: {}", args.show_report);
        println!("executed: {}", report);
    }
}
