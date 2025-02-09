#[crate_type = "lib"]
use openssl::hash::MessageDigest;

use byteorder::{BigEndian, ByteOrder};

use regex::Regex;
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
    pub static ref TOTP_ID_PATTERN: Regex = Regex::new(r"^([A-Za-z0-9]+):([A-Za-z0-9]+):([A-Za-z0-9]+):([0-9]+)?:([0-9]+)$").unwrap();
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

impl HashAlgo {
    pub fn get_message_digest(&self) -> openssl::hash::MessageDigest {
        match self {
            HashAlgo::Sha1 => MessageDigest::sha1(),
            HashAlgo::Sha256 => MessageDigest::sha256(),
            HashAlgo::Sha512 => MessageDigest::sha512(),
        }
    }
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

#[derive(Debug, PartialEq)]
pub struct OathCodeDisplay {
    code: u32,
    digits: u8,
}

impl OathCodeDisplay {
    pub fn new(bytes: &[u8; 5]) -> Self {
        Self {
            digits: bytes[0],
            code: BigEndian::read_u32(&bytes[1..5]),
        }
    }

    pub fn display(&self) -> String {
        format!("{:01$}", self.code, usize::from(self.digits))
    }
}
