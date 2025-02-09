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

pub struct ApduResponse {
    pub buf: Vec<u8>,
    pub sw1: u8,
    pub sw2: u8,
}

/// Sends the APDU package to the device
fn apdu(
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

fn apdu_read_all(
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
pub struct TransactionContext {
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

pub fn to_tlv(tag: Tag, value: &[u8]) -> Vec<u8> {
    Tlv::new(TlvTag::try_from(tag as u8).unwrap(), value.to_vec())
        .unwrap()
        .to_vec()
}

pub fn tlv_to_map(data: Vec<u8>) -> HashMap<u8, Vec<u8>> {
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

pub fn tlv_to_lists(data: Vec<u8>) -> HashMap<u8, Vec<Vec<u8>>> {
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
