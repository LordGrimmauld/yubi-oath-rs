extern crate byteorder;
/// Utilities for interacting with YubiKey OATH/TOTP functionality
extern crate pcsc;
use base32::Alphabet;
use iso7816_tlv::simple::{Tag as TlvTag, Tlv};
use once_cell::unsync::OnceCell;
use openssl::hash::MessageDigest;
use ouroboros::self_referencing;
use regex::Regex;
use std::collections::HashMap;
use std::default;
use std::iter::zip;
use std::str::{self};

use apdu_core::{Command, Response};

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use openssl::pkcs5::pbkdf2_hmac;
use pcsc::{Card, Transaction};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use byteorder::{BigEndian, ByteOrder, ReadBytesExt, WriteBytesExt};
use std::ffi::CString;
use std::io::{Cursor, Read};
use std::time::SystemTime;

pub const INS_SELECT: u8 = 0xa4;
pub const OATH_AID: [u8; 7] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

pub const DEFAULT_PERIOD: u32 = 30;
pub const DEFAULT_DIGITS: OathDigits = OathDigits::Six;
pub const DEFAULT_IMF: u32 = 0;

pub enum ErrorResponse {
    NoSpace = 0x6a84,
    CommandAborted = 0x6f00,
    InvalidInstruction = 0x6d00,
    AuthRequired = 0x6982,
    WrongSyntax = 0x6a80,
    GenericError = 0x6581,
    NoSuchObject = 0x6984,
}

lazy_static::lazy_static! {
    static ref TOTP_ID_PATTERN: Regex = Regex::new(r"^([A-Za-z0-9]+):([A-Za-z0-9]+):([A-Za-z0-9]+):([0-9]+)?:([0-9]+)$").unwrap();
}

pub enum SuccessResponse {
    MoreData = 0x61,
    Okay = 0x9000,
}

pub enum Instruction {
    Put = 0x01,
    Delete = 0x02,
    SetCode = 0x03,
    Reset = 0x04,
    Rename = 0x05,
    List = 0xa1,
    Calculate = 0xa2,
    Validate = 0xa3,
    CalculateAll = 0xa4,
    SendRemaining = 0xa5,
}

#[repr(u8)]
pub enum Mask {
    Algo = 0x0f,
    Type = 0xf0,
}

#[repr(u8)]
pub enum Tag {
    Name = 0x71,
    NameList = 0x72,
    Key = 0x73,
    Challenge = 0x74,
    Response = 0x75,
    TruncatedResponse = 0x76,
    Hotp = 0x77,
    Property = 0x78,
    Version = 0x79,
    Imf = 0x7a,
    Algorithm = 0x7b,
    Touch = 0x7c,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum HashAlgo {
    Sha1 = 0x01,
    Sha256 = 0x02,
    Sha512 = 0x03,
}

#[derive(Debug, PartialEq, Copy, Clone, Eq)]
#[repr(u8)]
pub enum OathType {
    Totp = 0x10,
    Hotp = 0x20,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OathDigits {
    Six = 6,
    Eight = 8,
}

pub struct ApduResponse {
    pub buf: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

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
    pub digits: OathDigits,
    pub value: u32,
    pub valid_from: u64,
    pub valid_to: u64,
}

#[derive(Debug)]
pub struct OathCredential<'a> {
    device_id: &'a str,
    id: Vec<u8>,
    issuer: Option<&'a str>,
    name: &'a str,
    oath_type: OathType,
    period: u64,
    touch_required: Option<bool>,
    //  TODO: Support this stuff
    //    pub oath_type: OathType,
    //    pub touch: bool,
    //    pub algo: OathAlgo,
    //    pub hidden: bool,
    //    pub steam: bool,
}

impl<'a> OathCredential<'a> {
    /* pub fn new(name: &str, code: OathCode) -> OathCredential {
        OathCredential {
            name,
            code,
            //            oath_type: oath_type,
            //            touch: touch,
            //            algo: algo,
            //            hidden: name.starts_with("_hidden:"),
            //            steam: name.starts_with("Steam:"),
        }
    } */
}

impl<'a> PartialOrd for OathCredential<'a> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = (
            self.issuer
                .clone()
                .unwrap_or_else(|| self.name)
                .to_lowercase(),
            self.name.to_lowercase(),
        );
        let b = (
            other
                .issuer
                .clone()
                .unwrap_or_else(|| other.name)
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
fn _parse_cred_id(cred_id: &[u8], oath_type: OathType) -> (Option<String>, String, u32) {
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

            return (Some(caps[4].to_string()), caps[5].to_string(), period);
        } else {
            return (None, data, DEFAULT_PERIOD);
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
    let mut hasher = Sha256::new();
    hasher.update(salt);
    let result = hasher.finalize();

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

fn get_message_digest(algo: HashAlgo) -> MessageDigest {
    match algo {
        HashAlgo::Sha1 => MessageDigest::sha1(),
        HashAlgo::Sha256 => MessageDigest::sha256(),
        HashAlgo::Sha512 => MessageDigest::sha512(),
    }
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

    let digits = truncated[0] as usize;

    // Convert the truncated bytes to an integer and mask with 0x7FFFFFFF, then apply mod 10^digits
    let code_value = BigEndian::read_u32(&truncated[1..]) & 0x7FFFFFFF; // Adjust endianess here
    let mod_value = 10u32.pow(digits as u32);
    let code_str = format!("{:0width$}", (code_value % mod_value), width = digits);

    OathCode {
        digits: if digits == 6 {
            OathDigits::Six
        } else if digits == 8 {
            OathDigits::Eight
        } else {
            panic!()
        },
        value: code_value,
        valid_from,
        valid_to,
    }
}

/// Sends the APDU package to the device
pub fn apdu(
    tx: &pcsc::Transaction,
    class: u8,
    instruction: u8,
    parameter1: u8,
    parameter2: u8,
    data: Option<&[u8]>,
) -> Result<ApduResponse, String> {
    let command = if let Some(data) = data {
        Command::new_with_payload(class, instruction, parameter1, parameter2, data)
    } else {
        Command::new(class, instruction, parameter1, parameter2)
    };

    let tx_buf: Vec<u8> = command.into();

    // Construct an empty buffer to hold the response
    let mut rx_buf = [0; pcsc::MAX_BUFFER_SIZE];

    // Write the payload to the device and error if there is a problem
    let rx_buf = match tx.transmit(&tx_buf, &mut rx_buf) {
        Ok(slice) => slice,
        Err(err) => return Err(format!("{}", err)),
    };

    let resp = Response::from(rx_buf);
    let error_context = to_error_response(resp.trailer.0, resp.trailer.1);

    if let Some(err) = error_context {
        return Err(err);
    }

    Ok(ApduResponse {
        buf: resp.payload.to_vec(),
        sw1: resp.trailer.0,
        sw2: resp.trailer.1,
    })
}

pub fn apdu_read_all(
    tx: &pcsc::Transaction,
    class: u8,
    instruction: u8,
    parameter1: u8,
    parameter2: u8,
    data: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let mut response_buf = Vec::new();
    let mut resp = apdu(tx, class, instruction, parameter1, parameter2, data)?;
    response_buf.extend(resp.buf);
    while resp.sw1 == (SuccessResponse::MoreData as u8) {
        resp = apdu(tx, 0, Instruction::SendRemaining as u8, 0, 0, None)?;
        response_buf.extend(resp.buf);
    }
    Ok(response_buf)
}

fn to_error_response(sw1: u8, sw2: u8) -> Option<String> {
    let code: usize = (sw1 as usize | sw2 as usize) << 8;

    match code {
        code if code == ErrorResponse::GenericError as usize => Some(String::from("Generic error")),
        code if code == ErrorResponse::NoSpace as usize => Some(String::from("No space on device")),
        code if code == ErrorResponse::NoSuchObject as usize => {
            Some(String::from("No such object"))
        }
        code if code == ErrorResponse::CommandAborted as usize => {
            Some(String::from("Command was aborted"))
        }
        code if code == ErrorResponse::AuthRequired as usize => {
            Some(String::from("Authentication required"))
        }
        code if code == ErrorResponse::WrongSyntax as usize => Some(String::from("Wrong syntax")),
        code if code == ErrorResponse::InvalidInstruction as usize => {
            Some(String::from("Invalid instruction"))
        }
        code if code == SuccessResponse::Okay as usize => None,
        sw1 if sw1 == SuccessResponse::MoreData as usize => None,
        _ => Some(String::from("Unknown error")),
    }
}

#[self_referencing]
struct TransactionContext {
    card: Card,
    #[borrows(mut card)]
    #[covariant]
    transaction: Transaction<'this>,
}

impl TransactionContext {
    pub fn from_name(name: &str) -> Self {
        // FIXME: error handling here

        // Establish a PC/SC context
        let ctx = pcsc::Context::establish(pcsc::Scope::User).unwrap();

        // Connect to the card
        let card = ctx
            .connect(
                &CString::new(name).unwrap(),
                pcsc::ShareMode::Shared,
                pcsc::Protocols::ANY,
            )
            .unwrap();

        TransactionContextBuilder {
            card,
            transaction_builder: |c| c.transaction().unwrap(),
        }
        .build()
    }

    pub fn apdu(
        &self,
        class: u8,
        instruction: u8,
        parameter1: u8,
        parameter2: u8,
        data: Option<&[u8]>,
    ) -> Result<ApduResponse, String> {
        apdu(
            self.borrow_transaction(),
            class,
            instruction,
            parameter1,
            parameter2,
            data,
        )
    }

    pub fn apdu_read_all(
        &self,
        class: u8,
        instruction: u8,
        parameter1: u8,
        parameter2: u8,
        data: Option<&[u8]>,
    ) -> Result<Vec<u8>, String> {
        apdu_read_all(
            self.borrow_transaction(),
            class,
            instruction,
            parameter1,
            parameter2,
            data,
        )
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
    pub fn get_oath_codes(&self) -> Result<Vec<LegacyOathCredential>, String> {
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

        let info_map = tlv_to_lists(response?);
        for (name_bytes, metadata) in zip(
            info_map.get(&(Tag::Name as u8)).unwrap(), // todo: error handling
            info_map.get(&(Tag::TruncatedResponse as u8)).unwrap(),
        ) {
            assert!(metadata.len() == 5);
            let name = str::from_utf8(&name_bytes).unwrap();
            let k_len = metadata.get(0).unwrap();
            let k_len_enum = match *k_len {
                6u8 => OathDigits::Six,
                8u8 => OathDigits::Eight,
                _ => continue,
            };

            let code = BigEndian::read_u32(&metadata[1..5]);

            key_buffer.push(LegacyOathCredential::new(
                name,
                OathCode {
                    digits: k_len_enum,
                    value: code,
                    valid_from: 0,
                    valid_to: 0x7FFFFFFFFFFFFFFF,
                },
            ));
        }
        return Ok(key_buffer);
    }
}

#[derive(Debug, PartialEq)]
pub struct LegacyOathCredential {
    pub name: String,
    pub code: OathCode,
    //  TODO: Support this stuff
    //    pub oath_type: OathType,
    //    pub touch: bool,
    //    pub algo: OathAlgo,
    //    pub hidden: bool,
    //    pub steam: bool,
}

impl LegacyOathCredential {
    pub fn new(name: &str, code: OathCode) -> LegacyOathCredential {
        LegacyOathCredential {
            name: name.to_string(),
            code: code,
            //            oath_type: oath_type,
            //            touch: touch,
            //            algo: algo,
            //            hidden: name.starts_with("_hidden:"),
            //            steam: name.starts_with("Steam:"),
        }
    }
}

fn to_tlv(tag: Tag, value: &[u8]) -> Vec<u8> {
    Tlv::new(TlvTag::try_from(tag as u8).unwrap(), value.to_vec())
        .unwrap()
        .to_vec()
}

fn tlv_to_map(data: Vec<u8>) -> HashMap<u8, Vec<u8>> {
    let mut buf: &[u8] = data.leak();
    let mut parsed_manual = HashMap::new();
    while !buf.is_empty() {
        let (r, remaining) = Tlv::parse(buf);
        buf = remaining;
        if let Ok(res) = r {
            parsed_manual.insert(res.tag().into(), res.value().to_vec());
        } else {
            println!("tlv parsing error");
            break; // Exit if parsing fails
        }
    }
    return parsed_manual;
}

fn tlv_to_lists(data: Vec<u8>) -> HashMap<u8, Vec<Vec<u8>>> {
    let mut buf: &[u8] = data.leak();
    let mut parsed_manual: HashMap<u8, Vec<Vec<u8>>> = HashMap::new();
    while !buf.is_empty() {
        let (r, remaining) = Tlv::parse(buf);
        buf = remaining;
        if let Ok(res) = r {
            parsed_manual
                .entry(res.tag().into())
                .or_insert_with(Vec::new)
                .push(res.value().to_vec());
        } else {
            println!("tlv parsing error");
            break; // Exit if parsing fails
        }
    }
    return parsed_manual;
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

pub fn legacy_format_code(code: u32, digits: OathDigits) -> String {
    let mut code_string = code.to_string();

    match digits {
        OathDigits::Six => {
            if code_string.len() <= 6 {
                format!("{:0>6}", code_string)
            } else {
                code_string.split_off(code_string.len() - 6)
            }
        }
        OathDigits::Eight => {
            if code_string.len() <= 8 {
                format!("{:0>8}", code_string)
            } else {
                code_string.split_off(code_string.len() - 8)
            }
        }
    }
}
