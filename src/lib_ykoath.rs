/// Utilities for interacting with YubiKey OATH/TOTP functionality

extern crate pcsc;
extern crate byteorder;

use std::ffi::{CString};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};
use std::time::{SystemTime};


pub type DetectResult<'a> = Result<Vec<YubiKey<'a>>, pcsc::Error>;

pub const INS_SELECT: u8 = 0xa4;
pub const OATH_AID: [u8; 7] = [0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01];

pub enum ErrorResponse {
    NoSpace = 0x6a84,
    CommandAborted = 0x6f00,
    InvalidInstruction = 0x6d00,
    AuthRequired = 0x6982,
    WrongSyntax = 0x6a80,
    GenericError = 0x6581,
    NoSuchObject = 0x6984,
}

pub enum SuccessResponse {
    MoreData = 0x61,
    Okay = 0x9000,
}

pub fn format_code(code: u32, digits: OathDigits) -> String {
    let mut code_string = code.to_string();

    match digits {
        OathDigits::Six => {
            if code_string.len() <= 6 {
                format!("{:0>6}", code_string)
            } else {
                code_string.split_off(code_string.len() - 6)
            }
        },
        OathDigits::Eight => {
            if code_string.len() <= 8 {
                format!("{:0>8}", code_string)
            } else {
                code_string.split_off(code_string.len() - 8)
            }
        },
    }
}

fn to_error_response(sw1: u8, sw2: u8) -> Option<String> {
    let code: usize = (sw1 as usize | sw2 as usize) << 8;
    
    match code {
        code if code == ErrorResponse::GenericError as usize => {
            Some(String::from("Generic error"))
        },
        code if code == ErrorResponse::NoSpace as usize => {
            Some(String::from("No space on device"))
        },
        code if code == ErrorResponse::CommandAborted as usize => {
            Some(String::from("Command was aborted"))
        },
        code if code == ErrorResponse::AuthRequired as usize => {
            Some(String::from("Authentication required"))
        },
        code if code == ErrorResponse::WrongSyntax as usize => {
            Some(String::from("Wrong syntax"))
        },
        code if code == ErrorResponse::InvalidInstruction as usize => {
            Some(String::from("Invalid instruction"))
        },
        code if code == SuccessResponse::Okay as usize => {
            None
        },
        sw1 if sw1 == SuccessResponse::MoreData as usize => {
            None
        },
        _ => {
            Some(String::from("Unknown error"))
        },
    }
}

fn to_tlv(tag: Tag, value: &[u8]) -> Vec<u8> {
    let mut buf = vec![tag as u8];
    let len = value.len();
    
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0xff {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.write_u16::<BigEndian>(len as u16).unwrap();
    }
    
    buf.write(value).unwrap();
    buf
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

pub enum Instruction {
    Put = 0x01,
    Delete = 0x02,
    SetCode = 0x03,
    Reset = 0x04,
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
pub enum OathAlgo {
    Sha1 = 0x01,
    Sha256 = 0x02,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum OathType {
    Totp = 0x10,
    Hotp = 0x20,
}

#[derive(Debug, PartialEq)]
pub struct OathCredential {
    pub name: String,
    pub code: OathCode,
//  TODO: Support this stuff
//    pub oath_type: OathType,
//    pub touch: bool,
//    pub algo: OathAlgo,
//    pub hidden: bool,
//    pub steam: bool,
}

impl OathCredential {
    pub fn new(name: &str, code: OathCode) -> OathCredential {
        OathCredential {
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

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OathDigits {
    Six = 6,
    Eight = 8,
}

#[derive(Debug, PartialEq)]
pub struct OathCode {
    pub digits: OathDigits,
    pub value: u32,
//    pub expiration: u32,
//    pub steam: bool,
}

pub struct ApduResponse {
    pub buf: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

pub struct YubiKey<'a> {
    pub name: &'a str,
}

impl<'a> YubiKey<'a> {   
    /// Read the OATH codes from the device
    pub fn get_oath_codes(&self) -> Result<Vec<OathCredential>, String>{
        // Establish a PC/SC context
        let ctx = match pcsc::Context::establish(pcsc::Scope::User) {
            Ok(ctx) => ctx,
            Err(err) => return Err(format!("{}", err)),
        };

        // Connect to the card
        let mut card = match ctx.connect(
            &CString::new(self.name).unwrap(), 
            pcsc::ShareMode::Shared, 
            pcsc::Protocols::ANY
        ) {
            Ok(card) => card,
            Err(err) => return Err(format!("{}", err)),
        };

        // Create a transaction context
        let tx = match card.transaction() {
            Ok(tx) => tx,
            Err(err) => return Err(format!("{}", err)),
        };

        // Switch to the OATH applet
        if let Err(e) = self.apdu(&tx, 0, INS_SELECT, 0x04, 0, Some(&OATH_AID)) {
            return Err(format!("{}", e));
        }

        // Store the response buffer
        let mut response_buf = Vec::new();

        // Request OATH codes from device
        let response = self.apdu(&tx, 0, Instruction::CalculateAll as u8, 0, 
            0x01, Some(&to_tlv(Tag::Challenge, 
                       &time_challenge(Some(SystemTime::now())))));

        // Handle errors from command
        match response {
            Ok(resp) => {
                let mut sw1 = resp.sw1;
                let mut sw2 = resp.sw2;
                response_buf.extend(resp.buf);

                while sw1 == (SuccessResponse::MoreData as u8) {
                    let ins = Instruction::SendRemaining as u8;

                    match self.apdu(&tx, 0, ins, 0, 0, None) {
                        Ok(more_resp) => {
                            sw1 = more_resp.sw1;
                            sw2 = more_resp.sw2;
                            response_buf.extend(more_resp.buf);
                        },
                        Err(e) => {
                            return Err(format!("{}", e));
                        },
                    }
                }

                if let Some(msg) = to_error_response(sw1, sw2) {
                    return Err(format!("{}", msg));
                }
 
                return Ok(self.parse_list(&response_buf).unwrap());
            },
            Err(e) => {
                return Err(format!("{}", e));
            }
        }
    }

    /// Accepts a raw byte buffer payload and parses it
    pub fn parse_list(&self, b: &[u8]) -> Result<Vec<OathCredential>, String> {
        let mut rdr = Cursor::new(b);
        let mut results = Vec::new();
        
        loop {
            if let Err(_) = rdr.read_u8() {
                break;
            };

            let mut len: u16 = match rdr.read_u8() {
                Ok(len) => len as u16,
                Err(_) => break,
            };

            if len > 0x80 {
                let n_bytes = len - 0x80;

                if n_bytes == 1 {
                    len = match rdr.read_u8() {
                        Ok(len) => len as u16,
                        Err(_) => break,
                    };
                } else if n_bytes == 2 {
                    len = match rdr.read_u16::<BigEndian>() {
                        Ok(len) => len,
                        Err(_) => break,
                    };
                }
            }

            let mut name = Vec::with_capacity(len as usize);

            unsafe {
                name.set_len(len as usize);
            }

            if let Err(_) = rdr.read_exact(&mut name) {
                break;
            };
           
            rdr.read_u8().unwrap(); // TODO: Don't discard the response tag
            rdr.read_u8().unwrap(); // TODO: Don't discard the response lenght + 1
            
            let digits = match rdr.read_u8() {
                Ok(6) => OathDigits::Six,
                Ok(8) => OathDigits::Eight,
                Ok(_) => break,
                Err(_) => break,
            };

            let value = match rdr.read_u32::<BigEndian>() {
                Ok(val) => val,
                Err(_) => break,
            };

            results.push(OathCredential::new(
                &String::from_utf8(name).unwrap(),
                OathCode { digits, value }
            ));
        }
    
        Ok(results)
    }

    /// Sends the APDU package to the device
    pub fn apdu(
        &self,
        tx: &pcsc::Transaction,
        class: u8, 
        instruction: u8, 
        parameter1: u8, 
        parameter2: u8, 
        data: Option<&[u8]>
    ) -> Result<ApduResponse, pcsc::Error> {
        // Create a container for the transaction payload
        let mut tx_buf = Vec::new();

        // Construct an empty buffer to hold the response
        let mut rx_buf = [0; pcsc::MAX_BUFFER_SIZE];

        // Number of bytes of data
        let nc = match data {
            Some(ref data) => data.len(),
            None => 0,
        };

        // Construct and attach the header
        tx_buf.push(class);
        tx_buf.push(instruction);
        tx_buf.push(parameter1);
        tx_buf.push(parameter2);
        
        // Construct and attach the data's byte count
        if nc > 255 {
            tx_buf.push(0);
            tx_buf.write_u16::<BigEndian>(nc as u16).unwrap();
        } else {
            tx_buf.push(nc as u8);
        }
        
        // Attach the data itself if included
        if let Some(data) = data {
            tx_buf.write(data).unwrap();
        }

        // DEBUG
        {
            let mut s = String::new();
            for byte in &tx_buf {
                s += &format!("{:02X} ", byte);
            } 
            println!("DEBUG (SEND) >> {}", s);
        }

        // Write the payload to the device and error if there is a problem
        let rx_buf = match tx.transmit(&tx_buf, &mut rx_buf) {
            Ok(slice) => slice,
            Err(err) => return Err(err),
        };

        // DEBUG
        {
            let mut s = String::new();
            for byte in &rx_buf.to_vec() {
                s += &format!("{:02X} ", byte);
            }
            println!("DEBUG (RECV) << {}", s);
        }

        let sw1 = match rx_buf.get((rx_buf.len() - 2) as usize) {
            Some(sw1) => sw1,
            None => return Err(pcsc::Error::UnknownError),
        };
        let sw2 = match rx_buf.get((rx_buf.len() - 1) as usize) {
            Some(sw2) => sw2,
            None => return Err(pcsc::Error::UnknownError),
        };

        let mut buf = rx_buf.to_vec();
        buf.truncate(rx_buf.len() - 2);

        Ok(ApduResponse {
            buf,
            sw1: *sw1, 
            sw2: *sw2,
        })
    }
}

