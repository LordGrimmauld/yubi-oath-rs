// SPDX-License-Identifier: BSD-3-Clause

use clap::{Args, Parser, Subcommand};
use ykoath2::{
    constants::OathType, oath_credential::OathCredential, oath_credential_id::CredentialIDData,
    OathSession,
};
// use clap::Parser;

#[derive(Subcommand)]
enum Commands {
    #[command(name = "store", about = "Store a credential")]
    Store {
        #[arg(help = "Credential name")]
        name: String,
        #[arg(help = "Credential type: Time-based or counter-based")]
        oath_type: String,
        #[arg(help = "Credential issuer")]
        issuer: Option<String>,
        #[arg(help = "Credential refresh period if it is time-based")]
        period: Option<u8>,
    },

    #[command(name = "tokens", about = "List all credentials for a device")]
    Tokens,

    #[command(name = "list", about = "List all connected devices")]
    List,
}

#[derive(Parser)]
#[clap(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[command(flatten)]
    args: Arguments,
}

#[derive(Args, Debug)]
struct Arguments {
    #[arg(name = "device", short, long, global = true, help = "Yubikey device")]
    device: Option<String>,
}

fn main() {
    let cli = Cli::parse();
    // Create a HID API context for detecting devices
    let context = pcsc::Context::establish(pcsc::Scope::User).unwrap();
    let mut readers_buf = [0; 2048];
    let devices = context
        .list_readers(&mut readers_buf)
        .unwrap()
        .into_iter()
        .map(|r| r.to_str().unwrap())
        .collect::<Vec<&str>>();

    // Show message if no YubiKey(s)
    if devices.is_empty() {
        println!("No yubikeys detected");
        std::process::exit(0);
    }

    match cli.command {
        Commands::Tokens => {
            let Some(selected_device) = cli.args.device else {
                println!("A device is required to store a credential.");
                std::process::exit(1);
            };
            if devices.iter().find(|d| **d == selected_device).is_none() {
                println!("{selected_device} was not found.");
                std::process::exit(1);
            }
            let session = OathSession::new(&selected_device).unwrap();
            for code in session.list_oath_codes().unwrap() {
                let oath_type = if code.oath_type() == OathType::Hotp {
                    "hotp"
                } else {
                    "totp"
                };
                println!(
                    "Name: {}, Issuer: {}, Type: {}",
                    code.name(),
                    code.issuer().unwrap_or_default(),
                    oath_type
                );
            }
        }
        Commands::Store {
            name,
            oath_type,
            issuer,
            period,
        } => {
            let Some(selected_device) = cli.args.device else {
                println!("A device is required to store a credential.");
                std::process::exit(1);
            };
            if devices.iter().find(|d| **d == selected_device).is_none() {
                println!("{selected_device} was not found.");
                std::process::exit(1);
            }
            let session = OathSession::new(&selected_device).unwrap();
            session
                .put_credential(
                    OathCredential::new(
                        &selected_device,
                        CredentialIDData::new(
                            &name,
                            ykoath2::constants::OathType::Totp,
                            issuer.as_deref(),
                            None,
                        ),
                        false,
                    ),
                    b"some secret",
                    ykoath2::constants::HashAlgo::Sha256,
                    6,
                    None,
                )
                .unwrap();
        }
        Commands::List => {
            // Print device info for all the YubiKeys we detected
            for device in devices {
                let session = OathSession::new(device).unwrap();
                println!("Device: {device}.");
                println!(
                    "Version: {:#?}.",
                    session
                        .version()
                        .iter()
                        .map(|v| v.to_string())
                        .collect::<Vec<_>>()
                        .join(".")
                );
            }
        }
    }
}
