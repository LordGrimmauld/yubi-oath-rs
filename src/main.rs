// SPDX-License-Identifier: BSD-3-Clause

mod args;
mod lib_ykoath2;

use lib_ykoath2::OathSession;
use pcsc;
use std::process;
// use crate::args::Cli;

// use clap::Parser;

fn main() {
    // let cli = Cli::parse();
    // Create a HID API context for detecting devices
    let context = pcsc::Context::establish(pcsc::Scope::User).unwrap();
    let mut readers_buf = [0; 2048];
    let readers = context.list_readers(&mut readers_buf).unwrap();

    // Initialize a vector to track all our detected devices
    let mut yubikeys: Vec<&str> = Vec::new();

    // Iterate over the connected USB devices
    for reader in readers {
        yubikeys.push(reader.to_str().unwrap());
    }

    // Show message if no YubiKey(s)
    if yubikeys.len() == 0 {
        println!("No yubikeys detected");
        process::exit(0);
    }

    // Print device info for all the YubiKeys we detected
    for yubikey in yubikeys {
        let device_label: &str = yubikey;
        println!("Found device with label {}", device_label);
        let session = OathSession::new(yubikey);
        let codes = match session.get_oath_codes() {
            Ok(codes) => codes,
            Err(e) => {
                println!("ERROR {}", e);
                continue;
            }
        };

        // Show message is node codes found
        if codes.len() == 0 {
            println!("No credentials on device {}", device_label);
        }

        // Enumerate the OATH codes
        for oath in codes {
            let code = lib_ykoath2::legacy_format_code(oath.code.value, oath.code.digits);
            let name_clone = oath.name.clone();
            let mut label_vec: Vec<&str> = name_clone.split(":").collect();
            let mut code_entry_label: String = String::from(label_vec.remove(0));

            if label_vec.len() > 0 {
                code_entry_label.push_str(" (");
                code_entry_label.push_str(&label_vec.join(""));
                code_entry_label.push_str(") ");
            }

            code_entry_label.push_str(&code.clone().to_owned());

            println!("Found OATH label: {}", code_entry_label);
        }
    }
}
