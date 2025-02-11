mod constants;
use constants::*;
mod transaction;
use transaction::*;
mod oath_credential;
mod oath_credentialid;
use oath_credential::*;
use oath_credentialid::*;
/// Utilities for interacting with YubiKey OATH/TOTP functionality
extern crate pcsc;
use pbkdf2::pbkdf2_hmac_array;
use sha1::Sha1;

use std::{
    str::{self},
    time::Duration,
};

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};

use std::time::SystemTime;

fn _get_device_id(salt: Vec<u8>) -> String {
    let result = HashAlgo::Sha256.get_hash_fun()(salt.leak());

    // Get the first 16 bytes of the hash
    let hash_16_bytes = &result[..16];

    // Base64 encode the result and remove padding ('=')
    return general_purpose::URL_SAFE_NO_PAD.encode(hash_16_bytes);
}
fn _hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("Invalid key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn _derive_key(salt: &[u8], passphrase: &str) -> Vec<u8> {
    pbkdf2_hmac_array::<Sha1, 16>(passphrase.as_bytes(), salt, 1000).to_vec()
}

fn _hmac_shorten_key(key: &[u8], algo: HashAlgo) -> Vec<u8> {
    if key.len() > algo.digest_size() {
        algo.get_hash_fun()(key)
    } else {
        key.to_vec()
    }
}

fn _get_challenge(timestamp: u32, period: u32) -> [u8; 8] {
    return ((timestamp / period) as u64).to_be_bytes();
}

pub struct OathSession<'a> {
    version: &'a [u8],
    salt: &'a [u8],
    challenge: &'a [u8],
    transaction_context: TransactionContext,
    pub name: String,
}

fn clone_with_lifetime<'a>(data: &'a [u8]) -> Vec<u8> {
    // Clone the slice into a new Vec<u8>
    data.to_vec() // `to_vec()` will return a Vec<u8> that has its own ownership
}

pub struct RefreshableOathCredential {
    cred: OathCredential,
    pub code: Option<OathCodeDisplay>,
    pub valid_from: u64,
    pub valid_to: u64,
    try_refresh_func: Option<Box<dyn Fn(OathCredential, SystemTime) -> Option<OathCodeDisplay>>>,
}

impl RefreshableOathCredential {
    pub fn new(cred: OathCredential) -> Self {
        RefreshableOathCredential {
            cred,
            code: None,
            valid_from: 0,
            valid_to: 0,
            try_refresh_func: None,
        }
    }

    pub fn force_update(&mut self, code: Option<OathCodeDisplay>, timestamp: SystemTime) {
        self.code = code;
        (self.valid_from, self.valid_to) =
            RefreshableOathCredential::format_validity_time_frame(&self, timestamp);
    }

    fn time_to_u64(timestamp: SystemTime) -> u64 {
        timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .as_ref()
            .map_or(0, Duration::as_secs)
    }

    pub fn display(&self) -> String {
        format!(
            "{}: {}",
            self.cred.id_data.name,
            self.code
                .as_ref()
                .map(OathCodeDisplay::display)
                .unwrap_or("".to_string())
        )
    }

    pub fn refresh(&mut self) {
        let timestamp = SystemTime::now();
        let refresh_result = if let Some(refresh_func) = self.try_refresh_func.as_deref() {
            refresh_func(self.cred.to_owned(), timestamp)
        } else {
            None
        };
        self.force_update(refresh_result, timestamp);
    }

    pub fn get_or_refresh(mut self) -> RefreshableOathCredential {
        if !self.is_valid() {
            self.refresh();
        }
        return self;
    }

    pub fn is_valid(&self) -> bool {
        let current_time = RefreshableOathCredential::time_to_u64(SystemTime::now());
        self.valid_from <= current_time && current_time <= self.valid_to
    }

    fn format_validity_time_frame(&self, timestamp: SystemTime) -> (u64, u64) {
        let timestamp_seconds = RefreshableOathCredential::time_to_u64(timestamp);
        match self.cred.id_data.oath_type {
            OathType::Totp => {
                let time_step = timestamp_seconds / (self.cred.id_data.period as u64);
                let valid_from = time_step * (self.cred.id_data.period as u64);
                let valid_to = (time_step + 1) * (self.cred.id_data.period as u64);
                (valid_from, valid_to)
            }
            OathType::Hotp => (timestamp_seconds, 0x7FFFFFFFFFFFFFFF),
        }
    }
}

impl<'a> OathSession<'a> {
    pub fn new(name: &str) -> Self {
        let transaction_context = TransactionContext::from_name(name);
        let info_buffer = transaction_context
            .apdu_read_all(0, INS_SELECT, 0x04, 0, Some(&OATH_AID))
            .unwrap();

        let info_map = tlv_to_map(info_buffer);
        for (tag, data) in &info_map {
            // Printing tag and data
            println!("{:?}: {:?}", tag, data);
        }

        OathSession {
            version: clone_with_lifetime(
                info_map.get(&(Tag::Version as u8)).unwrap_or(&vec![0u8; 0]),
            )
            .leak(),
            salt: clone_with_lifetime(info_map.get(&(Tag::Name as u8)).unwrap_or(&vec![0u8; 0]))
                .leak(),
            challenge: clone_with_lifetime(
                info_map
                    .get(&(Tag::Challenge as u8))
                    .unwrap_or(&vec![0u8; 0]),
            )
            .leak(),
            name: name.to_string(),
            transaction_context,
        }
    }

    pub fn get_version(&self) -> &[u8] {
        self.version
    }

    /// Read the OATH codes from the device
    pub fn get_oath_codes(&self) -> Result<Vec<RefreshableOathCredential>, String> {
        let timestamp = SystemTime::now();
        // Request OATH codes from device
        let response = self.transaction_context.apdu_read_all(
            0,
            Instruction::CalculateAll as u8,
            0,
            0x01,
            Some(&to_tlv(Tag::Challenge, &time_challenge(Some(timestamp)))),
        );

        let mut key_buffer = Vec::new();

        for (cred_id, meta) in TlvZipIter::from_vec(response?) {
            let touch = Into::<u8>::into(meta.tag()) == (Tag::Touch as u8); // touch only works with totp, this is intended
            let id_data = CredentialIDData::from_tlv(cred_id.value(), meta.tag());
            let code = OathCodeDisplay::from_tlv(meta);

            let cred = OathCredential {
                device_id: self.name.clone(),
                id_data,
                touch_required: touch,
            };

            let mut refreshable_cred = RefreshableOathCredential::new(cred); // todo: refresh callback
            refreshable_cred.force_update(code, timestamp);

            key_buffer.push(refreshable_cred);
        }

        return Ok(key_buffer);
    }
}

fn time_challenge(timestamp: Option<SystemTime>) -> [u8; 8] {
    (timestamp
        .unwrap_or_else(SystemTime::now)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30)
        .to_be_bytes()
}
