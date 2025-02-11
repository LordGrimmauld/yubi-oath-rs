#![crate_type = "lib"]
use crate::lib_ykoath2::*;
/// Utilities for interacting with YubiKey OATH/TOTP functionality
extern crate pcsc;
use regex::Regex;

use std::str::{self};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CredentialIDData {
    pub name: String,
    pub oath_type: OathType,
    pub issuer: Option<String>,
    pub period: u32,
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
