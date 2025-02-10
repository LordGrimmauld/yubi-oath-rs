extern crate byteorder;
mod constants;
use constants::*;
mod transaction;
use transaction::*;
/// Utilities for interacting with YubiKey OATH/TOTP functionality
extern crate pcsc;
use base32::Alphabet;
use openssl::hash::MessageDigest;
use sha1::Sha1;

use std::str::{self};

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use openssl::pkcs5::pbkdf2_hmac;

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use byteorder::{BigEndian, WriteBytesExt};
use std::time::SystemTime;

pub struct YubiKey<'a> {
    pub name: &'a str,
}

pub fn parse_b32_key(key: String) -> u32 {
    let stripped = key.to_uppercase().replace(" ", "");
    let pad = 8 - (stripped.len() % 8);
    let padded = stripped + (&"=".repeat(pad));
    let bytes = base32::decode(Alphabet::Rfc4648 { padding: true }, &padded).unwrap();
    let mut bytes_array: [u8; 4] = [0, 0, 0, 0];
    for i in 0..4 {
        bytes_array[i] = bytes.get(i).map(|x| *x).unwrap_or(0);
    }

    return u32::from_be_bytes(bytes_array); // fixme: be or le?
}

pub struct CredentialData<'a> {
    pub name: &'a str,
    oath_type: OathType,
    hash_algorithm: HashAlgo,
    // secret: bytes,
    digits: OathDigits, // = DEFAULT_DIGITS,
    period: u32,        // = DEFAULT_PERIOD,
    counter: u32,       // = DEFAULT_IMF,
    issuer: Option<&'a str>,
}

impl<'a> CredentialData<'a> {
    // TODO: parse_uri

    pub fn get_id(&self) -> Vec<u8> {
        return _format_cred_id(self.issuer, self.name, self.oath_type, self.period);
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
    issuer: Option<String>,
    name: String,
    oath_type: OathType,
    period: u64,
    touch_required: bool,
    pub code: Option<OathCodeDisplay>,
}

impl<'a> OathCredential<'a> {
    pub fn display(&self) -> String {
        format!(
            "{}: {}",
            self.name,
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
            self.issuer
                .clone()
                .unwrap_or_else(|| self.name.clone())
                .to_lowercase(),
            self.name.to_lowercase(),
        );
        let b = (
            other
                .issuer
                .clone()
                .unwrap_or_else(|| other.name.clone())
                .to_lowercase(),
            other.name.to_lowercase(),
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

fn _format_cred_id(issuer: Option<&str>, name: &str, oath_type: OathType, period: u32) -> Vec<u8> {
    let mut cred_id = String::new();

    if oath_type == OathType::Totp && period != DEFAULT_PERIOD {
        cred_id.push_str(&format!("{}/", period));
    }

    if let Some(issuer) = issuer {
        cred_id.push_str(&format!("{}:", issuer));
    }

    cred_id.push_str(name);
    return cred_id.into_bytes(); // Convert the string to bytes
}

// Function to parse the credential ID
fn _parse_cred_id(cred_id: &[u8], oath_type: OathType) -> (Option<String>, String, u64) {
    let data = match str::from_utf8(cred_id) {
        Ok(d) => d.to_string(),
        Err(_) => return (None, String::new(), 0), // Handle invalid UTF-8
    };

    if oath_type == OathType::Totp {
        if let Some(caps) = TOTP_ID_PATTERN.captures(&data) {
            let period_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
            let period = if !period_str.is_empty() {
                period_str.parse::<u32>().unwrap_or(DEFAULT_PERIOD)
            } else {
                DEFAULT_PERIOD
            };

            return (
                Some(caps[4].to_string()),
                caps[5].to_string(),
                period.into(),
            );
        } else {
            return (None, data, DEFAULT_PERIOD.into());
        }
    } else {
        let (issuer, rest) = if let Some(pos) = data.find(':') {
            if data.chars().next() != Some(':') {
                let issuer = data[..pos].to_string();
                let rest = data[pos + 1..].to_string();
                (Some(issuer), rest)
            } else {
                (None, data)
            }
        } else {
            (None, data)
        };

        return (issuer, rest, 0);
    }
}

fn _get_device_id(salt: Vec<u8>) -> String {
    // Create SHA-256 hash of the salt
    let mut hasher = openssl::hash::Hasher::new(MessageDigest::sha256()).unwrap();
    hasher.update(salt.leak()).unwrap();
    let result = hasher.finish().unwrap();

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
    let mut key = vec![0u8; 16]; // Allocate 16 bytes for the key
    pbkdf2_hmac(
        passphrase.as_bytes(),
        salt,
        1000,
        MessageDigest::sha1(),
        &mut key,
    )
    .unwrap();
    key
}

fn _hmac_shorten_key(key: &[u8], algo: MessageDigest) -> Vec<u8> {
    if key.len() > algo.block_size() {
        let mut hasher = openssl::hash::Hasher::new(algo).unwrap();
        hasher.update(key).unwrap();
        return hasher.finish().unwrap().to_vec();
    }

    key.to_vec()
}

fn _get_challenge(timestamp: u32, period: u32) -> [u8; 8] {
    let time_step = timestamp / period;

    let mut buffer = [0u8; 8];
    let mut cursor = &mut buffer[..];
    cursor.write_u64::<BigEndian>(time_step as u64).unwrap();

    buffer
}

fn format_code(credential: &OathCredential, timestamp: u64, truncated: &[u8]) -> OathCode {
    let (valid_from, valid_to) = match credential.oath_type {
        OathType::Totp => {
            let time_step = timestamp / credential.period;
            let valid_from = time_step * credential.period;
            let valid_to = (time_step + 1) * credential.period;
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
            // let name = str::from_utf8(&cred_id.value()).unwrap();
            let oath_type = if Into::<u8>::into(meta.tag()) == (Tag::Hotp as u8) {
                OathType::Hotp
            } else {
                OathType::Totp
            };
            let touch = Into::<u8>::into(meta.tag()) == (Tag::Touch as u8); // touch only works with totp, this is intended
            let (issuer, name, period) = _parse_cred_id(cred_id.value(), oath_type);
            let cred = OathCredential {
                device_id: &self.name,
                id: meta.value().to_vec(),
                issuer,
                name,
                period,
                touch_required: touch,
                oath_type,
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
    let mut buf = Vec::new();
    let ts = match timestamp {
        Some(datetime) => {
            datetime
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 30
        }
        None => {
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                / 30
        }
    };
    buf.write_u64::<BigEndian>(ts).unwrap();
    buf
}
