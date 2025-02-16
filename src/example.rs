// SPDX-License-Identifier: BSD-3-Clause

use ykoath2::OathSession;
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
    if yubikeys.is_empty() {
        println!("No yubikeys detected");
        std::process::exit(0);
    }

    // Print device info for all the YubiKeys we detected
    for yubikey in yubikeys {
        let device_label: &str = yubikey;
        println!("Found device with label {}", device_label);
        let session = OathSession::new(yubikey).unwrap();

        /* session.set_key(&session.derive_key("1234")).unwrap();
        session.unlock_session(&session.derive_key("1234")).unwrap();
        session.unset_key().unwrap();

        let cred = OathCredential {
            device_id: session.name.clone(),
            id_data: CredentialIDData {
                name: "test_cred".to_string(),
                oath_type: OathType::Totp,
                issuer: None,
                period: DEFAULT_PERIOD,
            },
            touch_required: false,
        };

        session
            .put_credential(
                cred.clone(),
                "f5up4ub3dw".as_bytes(),
                HashAlgo::Sha256,
                6,
                None,
            )
            .unwrap();
        let calculated = session.calculate_refreshable_code(&cred, None).unwrap();
        println!("freshly defined oath: {}", calculated);
        session.delete_code(cred).unwrap(); */

        println!("YubiKey version is {:?}", session.version());
        for c in session.list_oath_codes().unwrap() {
            println!("{}", c);
        }

        let codes = match session.calculate_oath_codes() {
            Ok(codes) => codes,
            Err(e) => {
                println!("ERROR {}", e);
                continue;
            }
        };

        // Show message is node codes found
        if codes.is_empty() {
            println!("No credentials on device {}", device_label);
        }

        std::thread::sleep(std::time::Duration::from_secs(0)); // show refresh is working

        // Enumerate the OATH codes
        for oath in codes {
            // let recalculated = session.calculate_code(oath.cred, None).unwrap();
            println!("Found OATH label: {}", oath.get_or_refresh());
        }
    }
}
