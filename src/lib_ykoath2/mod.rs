mod constants;
use constants::*;
mod transaction;
use transaction::*;
/// Utilities for interacting with YubiKey OATH/TOTP functionality
extern crate pcsc;
use pbkdf2::pbkdf2_hmac_array;
use regex::Regex;
use sha1::Sha1;

use std::str::{self};

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use std::time::SystemTime;

#[derive(Debug)]
pub struct CredentialIDData {
    pub name: String,
    oath_type: OathType,
    issuer: Option<String>,
    period: u32,
}

impl CredentialIDData {
    pub fn from_tlv(id_bytes: &[u8], oath_type_tag: iso7816_tlv::simple::Tag) -> Self {
        let oath_type = if Into::<u8>::into(oath_type_tag) == (Tag::Hotp as u8) {
            OathType::Hotp
        } else {
            OathType::Totp
        };
        let (issuer, name, period) = CredentialIDData::parse_cred_id(id_bytes, oath_type);
        return CredentialIDData {
            issuer,
            name,
            period,
            oath_type,
        };
    }

    pub fn format_cred_id(&self) -> Vec<u8> {
        let mut cred_id = String::new();

        if self.oath_type == OathType::Totp && self.period != DEFAULT_PERIOD {
            cred_id.push_str(&format!("{}/", self.period));
        }

        if let Some(issuer) = self.issuer.as_deref() {
            cred_id.push_str(&format!("{}:", issuer));
        }

        cred_id.push_str(self.name.as_str());
        return cred_id.into_bytes(); // Convert the string to bytes
    }
    fn format_code(&self, timestamp: u64, truncated: &[u8]) -> OathCode {
        let (valid_from, valid_to) = match self.oath_type {
            OathType::Totp => {
                let time_step = timestamp / (self.period as u64);
                let valid_from = time_step * (self.period as u64);
                let valid_to = (time_step + 1) * (self.period as u64);
                (valid_from, valid_to)
            }
            OathType::Hotp => (timestamp, 0x7FFFFFFFFFFFFFFF),
        };

        OathCode {
            display: OathCodeDisplay::new(truncated[..].try_into().unwrap()),
            valid_from,
            valid_to,
        }
    }

    // Function to parse the credential ID
    fn parse_cred_id(cred_id: &[u8], oath_type: OathType) -> (Option<String>, String, u32) {
        let data = match str::from_utf8(cred_id) {
            Ok(d) => d,
            Err(_) => return (None, String::new(), 0), // Handle invalid UTF-8
        };

        if oath_type == OathType::Totp {
            Regex::new(r"^((\d+)/)?(([^:]+):)?(.+)$")
                .ok()
                .and_then(|r| r.captures(&data))
                .map_or((None, data.to_string(), DEFAULT_PERIOD), |caps| {
                    let period = (&caps.get(2))
                        .and_then(|s| s.as_str().parse::<u32>().ok())
                        .unwrap_or(DEFAULT_PERIOD);
                    return (Some(caps[4].to_string()), caps[5].to_string(), period);
                })
        } else {
            return data
                .split_once(':')
                .map_or((None, data.to_string(), 0), |(i, n)| {
                    (Some(i.to_string()), n.to_string(), 0)
                });
        }
    }
}

pub struct CredentialData {
    id_data: CredentialIDData,
    hash_algorithm: HashAlgo,
    // secret: bytes,
    digits: OathDigits, // = DEFAULT_DIGITS,
    counter: u32,       // = DEFAULT_IMF,
}

impl CredentialData {
    // TODO: parse_uri

    pub fn get_id(&self) -> Vec<u8> {
        return self.id_data.format_cred_id();
    }
}

#[derive(Debug, PartialEq)]
pub struct OathCode {
    pub display: OathCodeDisplay,
    pub valid_from: u64,
    pub valid_to: u64,
}

#[derive(Debug)]
pub struct OathCredential<'a> {
    device_id: &'a str,
    id: Vec<u8>,
    id_data: CredentialIDData,
    touch_required: bool,
    pub code: Option<OathCodeDisplay>,
}

impl<'a> OathCredential<'a> {
    pub fn display(&self) -> String {
        format!(
            "{}: {}",
            self.id_data.name,
            self.code
                .as_ref()
                .map(OathCodeDisplay::display)
                .unwrap_or("".to_string())
        )
    }
}

impl<'a> PartialOrd for OathCredential<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = (
            self.id_data
                .issuer
                .clone()
                .unwrap_or_else(|| self.id_data.name.clone())
                .to_lowercase(),
            self.id_data.name.to_lowercase(),
        );
        let b = (
            other
                .id_data
                .issuer
                .clone()
                .unwrap_or_else(|| other.id_data.name.clone())
                .to_lowercase(),
            other.id_data.name.to_lowercase(),
        );
        Some(a.cmp(&b))
    }
}

impl<'a> PartialEq for OathCredential<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.device_id == other.device_id && self.id == other.id
    }
}

impl<'a> Hash for OathCredential<'a> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.device_id.hash(state);
        self.id.hash(state);
    }
}

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
    pub fn get_oath_codes(&self) -> Result<Vec<OathCredential>, String> {
        // Request OATH codes from device
        let response = self.transaction_context.apdu_read_all(
            0,
            Instruction::CalculateAll as u8,
            0,
            0x01,
            Some(&to_tlv(
                Tag::Challenge,
                &time_challenge(Some(SystemTime::now())),
            )),
        );

        let mut key_buffer = Vec::new();

        for (cred_id, meta) in TlvZipIter::from_vec(response?) {
            let touch = Into::<u8>::into(meta.tag()) == (Tag::Touch as u8); // touch only works with totp, this is intended
            let id_data = CredentialIDData::from_tlv(cred_id.value(), meta.tag());
            let cred = OathCredential {
                device_id: &self.name,
                id: meta.value().to_vec(),
                id_data,
                touch_required: touch,
                code: if Into::<u8>::into(meta.tag()) == (Tag::TruncatedResponse as u8) {
                    assert!(meta.value().len() == 5);
                    let display = OathCodeDisplay::new(meta.value()[..].try_into().unwrap());
                    Some(display)
                } else {
                    None
                },
            };
            key_buffer.push(cred);
        }

        return Ok(key_buffer);
    }
}

fn time_challenge(timestamp: Option<SystemTime>) -> Vec<u8> {
    (timestamp
        .unwrap_or_else(SystemTime::now)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30)
        .to_be_bytes()
        .to_vec()
}
