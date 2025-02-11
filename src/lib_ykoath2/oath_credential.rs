#[crate_type = "lib"]
use crate::lib_ykoath2::*;
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

#[derive(Debug, Clone)]
pub struct OathCredential {
    pub device_id: String,
    pub id_data: CredentialIDData,
    pub touch_required: bool,
}

impl PartialOrd for OathCredential {
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

impl<'a> PartialEq for OathCredential {
    fn eq(&self, other: &Self) -> bool {
        self.device_id == other.device_id && self.id_data == other.id_data
    }
}

impl<'a> Hash for OathCredential {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.device_id.hash(state);
        self.id_data.format_cred_id().hash(state);
    }
}
