use sp1_sdk::{include_elf, utils, ProverClient, SP1Stdin};

pub const ELF: &[u8] = include_elf!("bls_share_prove");
use std::env;
use clap::Parser;
use dvt_abi;
use dvt_abi_host;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long)]
    execute: bool,

    #[arg(long = "input-file")]
    input_file: String,
}

fn main(){
    let args = Cli::parse();

    if args.input_file.is_empty() {
        eprintln!("No file name provided after '--input-file'.");
        std::process::exit(1);
    }

    let data = dvt_abi::read_share_data_from_file(&args.input_file);


    utils::setup_logger();

    let mut stdin = SP1Stdin::new();

    let client = ProverClient::new();

    match data {
        Ok(data) => {
            
            let abi_data = dvt_abi::to_abi_bls_data(&data);            
            match abi_data {
                Ok(abi_data) => {
                    dvt_abi_host::abi_bls_share_data_write_to_prover(&mut stdin, &abi_data);
                }
                Err(e) => {
                    println!("Error: {}", e);
                }
            }
        }
        Err(e) => {
            println!("Error parsing JSON: {}", e);
        }
    }
    
    
    let (_public_values, report) = client.execute(ELF, stdin).run().expect("failed to prove");

    println!("executed: {}", report);
}
