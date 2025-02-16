use std::{fmt::Display, time::Duration};

use iso7816_tlv::simple::Tlv;
use sha1::Digest;

/// te apdu instruction required to select the Oath application on the YubiKey
pub const INS_SELECT: u8 = 0xa4;

/// the stream of data bytes required to select the Oath application on the YubiKey
pub const OATH_AID: [u8; 7] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

/// The default duration that generated codes are valid for is 30 seconds.
/// Non-default values are saved and retrieved from the YubiKey.
/// If not explicitly declared otherwise, this is the fallback that will be used.
pub const DEFAULT_PERIOD: Duration = Duration::from_secs(30);

/// Oath keys on the YubiKey are stored by a handle.
/// If the original handle is too long, it will be shortend to an hmac.
/// If the key is too short, it will be padded to have the minimum length.
pub const HMAC_MINIMUM_KEY_SIZE: usize = 14;

/// Error Response codes as returned by the YubiKey
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorResponse {
    NoSpace = 0x6a84,
    CommandAborted = 0x6f00,
    InvalidInstruction = 0x6d00,
    AuthRequired = 0x6982,
    WrongSyntax = 0x6a80,
    GenericError = 0x6581,
    NoSuchObject = 0x6984,
}

impl ErrorResponse {
    pub fn any_match(code: u16) -> Option<ErrorResponse> {
        if code == ErrorResponse::NoSpace as u16 {
            Some(ErrorResponse::NoSpace)
        } else if code == ErrorResponse::CommandAborted as u16 {
            Some(ErrorResponse::CommandAborted)
        } else if code == ErrorResponse::InvalidInstruction as u16 {
            Some(ErrorResponse::InvalidInstruction)
        } else if code == ErrorResponse::AuthRequired as u16 {
            Some(ErrorResponse::AuthRequired)
        } else if code == ErrorResponse::WrongSyntax as u16 {
            Some(ErrorResponse::WrongSyntax)
        } else if code == ErrorResponse::GenericError as u16 {
            Some(ErrorResponse::GenericError)
        } else if code == ErrorResponse::NoSuchObject as u16 {
            Some(ErrorResponse::NoSuchObject)
        } else {
            None
        }
    }
}

impl std::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSpace => f.write_str("No Space left on device"),
            Self::CommandAborted => f.write_str("Command aborted"),
            Self::InvalidInstruction => f.write_str("Invalid instruction"),
            Self::AuthRequired => f.write_str("Authentication required"),
            Self::WrongSyntax => f.write_str("Wrong syntax"),
            Self::GenericError => f.write_str("Generic Error"),
            Self::NoSuchObject => f.write_str("No such Object"),
        }
    }
}

impl std::error::Error for ErrorResponse {}

/// Success response codes as returned by the YubiKey
#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum SuccessResponse {
    MoreData = 0x61,
    Okay = 0x9000,
}

impl SuccessResponse {
    pub fn any_match(code: u16) -> Option<SuccessResponse> {
        if code == SuccessResponse::MoreData as u16 {
            Some(SuccessResponse::MoreData)
        } else if code == SuccessResponse::Okay as u16 {
            Some(SuccessResponse::Okay)
        } else {
            None
        }
    }
}

/// Set of possible instructions to use with the YubiKey via apdu
#[repr(u8)]
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

/// possible tlv tag values to use with apdu
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

/// Different Hash algorithms supported by the YubiKey to generate OTPs
#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum HashAlgo {
    Sha1 = 0x01,
    Sha256 = 0x02,
    Sha512 = 0x03,
}

impl HashAlgo {
    /// returns a function capable of hashing a byte array
    /// necessary to be able to validate keys before enrolling them on the hardware key
    pub fn get_hash_fun(&self) -> impl Fn(&[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => |m: &[u8]| {
                let mut hasher = sha1::Sha1::new();
                hasher.update(m);
                hasher.finalize().to_vec()
            },
            Self::Sha256 => |m: &[u8]| {
                let mut hasher = sha2::Sha256::new();
                hasher.update(m);
                hasher.finalize().to_vec()
            },
            Self::Sha512 => |m: &[u8]| {
                let mut hasher = sha2::Sha512::new();
                hasher.update(m);
                hasher.finalize().to_vec()
            },
        }
    }

    /// returns digest output size in number of bytes
    pub fn digest_size(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}

/// different types of oath to generate OTPs
#[derive(Debug, PartialEq, Copy, Clone, Eq, Hash)]
#[repr(u8)]
pub enum OathType {
    Hotp = 0x10,
    Totp = 0x20,
}

/// describes display information of a code, keeping track of the code and number of digits
/// digits *should* be either 6 or 8, but nothing is preventing the yubikey from returning e.g. 7 digits, which would "just work".
#[derive(Debug, PartialEq, Hash, Eq, Copy, Clone)]
pub struct OathCodeDisplay {
    code: u32,
    digits: u8,
}

impl Display for OathCodeDisplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:01$}", self.code, usize::from(self.digits)))
    }
}

impl OathCodeDisplay {
    /// extracts display information (digits and code) from a `Tlv` instance
    pub fn from_tlv(tlv: Tlv) -> Option<Self> {
        if Into::<u8>::into(tlv.tag()) == (Tag::TruncatedResponse as u8) {
            TryInto::<&[u8; 5]>::try_into(tlv.value())
                .ok()
                .and_then(OathCodeDisplay::new)
        } else {
            None
        }
    }

    /// extract display information from a 5-bytes buffer
    pub fn new(bytes: &[u8; 5]) -> Option<Self> {
        TryInto::<[u8; 4]>::try_into(&bytes[1..])
            .ok()
            .map(|code_bytes| Self {
                digits: bytes[0],
                code: u32::from_be_bytes(code_bytes),
            })
    }
}
