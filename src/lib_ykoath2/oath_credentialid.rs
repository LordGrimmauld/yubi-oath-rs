#![crate_type = "lib"]
use crate::lib_ykoath2::*;
/// Utilities for interacting with YubiKey OATH/TOTP functionality
extern crate pcsc;
use regex::Regex;

use std::{
    fmt::Write,
    str::{self},
};

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CredentialIDData {
    pub name: String,
    pub oath_type: OathType,
    pub issuer: Option<String>,
    pub period: u32,
}

impl Display for CredentialIDData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(i) = self.issuer.clone() {
            f.write_fmt(format_args!("{}: ", i))?;
        }
        f.write_str(&self.name)
    }
}

impl CredentialIDData {
    pub fn from_tlv(id_bytes: &[u8], oath_type_tag: iso7816_tlv::simple::Tag) -> Self {
        return CredentialIDData::from_bytes(id_bytes, Into::<u8>::into(oath_type_tag));
    }

    pub fn as_tlv(&self) -> Vec<u8> {
        return to_tlv(Tag::Name, &self.format_cred_id());
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

    pub(crate) fn from_bytes(id_bytes: &[u8], tag: u8) -> CredentialIDData {
        let oath_type = if tag == (Tag::Hotp as u8) {
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
}
