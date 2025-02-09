#[crate_type = "lib"]
extern crate byteorder;
use crate::lib_ykoath2::*;
/// Utilities for interacting with YubiKey OATH/TOTP functionality
extern crate pcsc;
use base32::Alphabet;
use iso7816_tlv::simple::{Tag as TlvTag, Tlv};
use openssl::hash::MessageDigest;
use sha1::Sha1;

use ouroboros::self_referencing;
use regex::Regex;
use std::collections::HashMap;
use std::iter::zip;
use std::str::{self};

use apdu_core::{Command, Response};

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use openssl::pkcs5::pbkdf2_hmac;
use pcsc::{Card, Transaction};

use std::cmp::Ordering;
use std::hash::{Hash, Hasher};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use std::ffi::CString;
use std::time::SystemTime;

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
