use std::{
    fmt::Display,
    hash::{Hash, Hasher},
    time::Duration,
};

use regex::Regex;

use crate::{to_tlv, OathType, Tag, DEFAULT_PERIOD};

/// holds data on one credential.
/// Acts as a handle to credentials when requesting codes from the YubiKey.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct CredentialIDData {
    /// name of a credential.
    /// Typically specifies an account.
    name: String,

    /// One of `OathType::Totp` or `OathType::Hotp`.
    /// Specifies the type of OTP used represented by this credential.
    oath_type: OathType,

    /// issuer of the credential.
    /// Typically specifies the platform.
    issuer: Option<String>,

    /// validity period of each generated code.
    period: Option<Duration>,
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
    /// reads id data from tlv data
    /// `id_bytes` refers to the byte buffer containing issuer, name and period
    /// `oath_type_tag` refers to the tlv tag containing the oath type information
    pub fn from_tlv(id_bytes: &[u8], oath_type_tag: iso7816_tlv::simple::Tag) -> Self {
        let oath_type = if Into::<u8>::into(oath_type_tag) == Tag::Hotp as u8 {
            OathType::Hotp
        } else {
            OathType::Totp
        };
        CredentialIDData::from_bytes(id_bytes, oath_type)
    }

    /// Reconstructs the tlv data to refer to this credential on the YubiKey
    pub fn as_tlv(&self) -> Vec<u8> {
        to_tlv(Tag::Name, &self.format_cred_id())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    pub fn oath_type(&self) -> OathType {
        self.oath_type
    }

    /// Returns the defined period or default
    pub fn period(&self) -> Duration {
        self.period.unwrap_or(DEFAULT_PERIOD)
    }

    fn format_cred_id(&self) -> Vec<u8> {
        let mut cred_id = String::new();

        if self.oath_type == OathType::Totp {
            if let Some(p) = self.period {
                cred_id.push_str(&format!("{}/", p.as_secs()));
            }
        }

        if let Some(issuer) = self.issuer.as_deref() {
            cred_id.push_str(&format!("{}:", issuer));
        }

        cred_id.push_str(self.name.as_str());
        cred_id.into_bytes() // Convert the string to bytes
    }

    fn parse_cred_id(
        cred_id: &[u8],
        oath_type: OathType,
    ) -> (Option<String>, String, Option<Duration>) {
        let data = match std::str::from_utf8(cred_id) {
            Ok(d) => d,
            Err(_) => return (None, String::new(), Some(Duration::ZERO)), // Handle invalid UTF-8
        };

        if oath_type == OathType::Totp {
            Regex::new(r"^((\d+)/)?(([^:]+):)?(.+)$")
                .ok()
                .and_then(|r| r.captures(data))
                .map_or((None, data.to_string(), None), |caps| {
                    let period = caps
                        .get(2)
                        .and_then(|s| s.as_str().parse::<u32>().ok())
                        .map(|t| Duration::from_secs(t as u64))
                        .unwrap_or(DEFAULT_PERIOD);
                    let issuer = caps.get(4).map(|m| m.as_str().to_string());
                    let cred_name = caps.get(5).map_or(data, |m| m.as_str());
                    (issuer, cred_name.to_string(), Some(period))
                })
        } else {
            data.split_once(':')
                .map_or((None, data.to_string(), None), |(i, n)| {
                    (Some(i.to_string()), n.to_string(), None)
                })
        }
    }

    /// parses a credential id from byte buffers
    /// `id_bytes` contains information about issuer, name and duration
    pub fn from_bytes(id_bytes: &[u8], oath_type: OathType) -> CredentialIDData {
        let (issuer, name, period) = CredentialIDData::parse_cred_id(id_bytes, oath_type);
        CredentialIDData {
            issuer,
            name,
            period,
            oath_type,
        }
    }
}

impl Hash for CredentialIDData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.format_cred_id().hash(state);
    }
}
