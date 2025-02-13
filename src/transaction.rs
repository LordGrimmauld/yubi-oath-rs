use std::{collections::HashMap, ffi::CString, fmt::Display};

use apdu_core::{Command, Response};
use iso7816_tlv::simple::{Tag as TlvTag, Tlv};
use ouroboros::self_referencing;
use pcsc::{Card, Transaction};

use crate::{ErrorResponse, Instruction, SuccessResponse, Tag};

#[derive(PartialEq, Eq, Debug)]
pub enum Error {
    Unknown(String),
    Protocol(ErrorResponse),
    Pcsc(pcsc::Error),
    Parsing(String),
    DeviceMismatch,
}

impl Error {
    fn from_apdu_response(sw1: u8, sw2: u8) -> Result<(), Self> {
        let code: u16 = (sw1 as u16 | sw2 as u16) << 8;
        if let Some(e) = ErrorResponse::any_match(code) {
            return Err(Self::Protocol(e));
        }
        if SuccessResponse::any_match(code)
            .or(SuccessResponse::any_match(sw1.into()))
            .is_some()
        {
            return Ok(());
        }
        Err(Self::Unknown(String::from("Unknown error")))
    }
}

impl From<pcsc::Error> for Error {
    fn from(value: pcsc::Error) -> Self {
        Self::Pcsc(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(msg) => f.write_str(msg),
            Self::Protocol(error_response) => f.write_fmt(format_args!("{}", error_response)),
            Self::Pcsc(error) => f.write_fmt(format_args!("{}", error)),
            Self::Parsing(msg) => f.write_str(msg),
            Self::DeviceMismatch => f.write_str("Devices do not match"),
        }
    }
}

impl std::error::Error for Error {}

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
) -> Result<ApduResponse, Error> {
    let command = if let Some(data) = data {
        Command::new_with_payload(class, instruction, parameter1, parameter2, data)
    } else {
        Command::new(class, instruction, parameter1, parameter2)
    };

    let tx_buf: Vec<u8> = command.into();

    // Construct an empty buffer to hold the response
    let mut rx_buf = [0; pcsc::MAX_BUFFER_SIZE];

    // Write the payload to the device and error if there is a problem
    let rx_buf = tx.transmit(&tx_buf, &mut rx_buf)?;
    let resp = Response::from(rx_buf);
    Error::from_apdu_response(resp.trailer.0, resp.trailer.1)?;

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
) -> Result<Vec<u8>, Error> {
    let mut response_buf = Vec::new();
    let mut resp = apdu(tx, class, instruction, parameter1, parameter2, data)?;
    response_buf.extend(resp.buf);
    while resp.sw1 == (SuccessResponse::MoreData as u8) {
        resp = apdu(tx, 0, Instruction::SendRemaining as u8, 0, 0, None)?;
        response_buf.extend(resp.buf);
    }
    Ok(response_buf)
}

#[self_referencing]
pub struct TransactionContext {
    card: Card,
    #[borrows(mut card)]
    #[covariant]
    transaction: Transaction<'this>,
}

impl TransactionContext {
    pub fn from_name(name: &str) -> Result<Self, Error> {
        // Establish a PC/SC context
        let ctx = pcsc::Context::establish(pcsc::Scope::User)?;

        // Connect to the card
        let card = ctx.connect(
            &CString::new(name).unwrap(),
            pcsc::ShareMode::Shared,
            pcsc::Protocols::ANY,
        )?;

        Ok(TransactionContextBuilder {
            card,
            transaction_builder: |c| c.transaction().unwrap(),
        }
        .build())
    }

    pub fn apdu(
        &self,
        class: u8,
        instruction: u8,
        parameter1: u8,
        parameter2: u8,
        data: Option<&[u8]>,
    ) -> Result<ApduResponse, Error> {
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
    ) -> Result<Vec<u8>, Error> {
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
    let mut parsed_manual = HashMap::new();
    for res in TlvIter::from_vec(data) {
        parsed_manual.insert(res.tag().into(), res.value().to_vec());
    }
    parsed_manual
}

pub struct TlvZipIter<'a> {
    iter: TlvIter<'a>,
}

impl<'a> TlvZipIter<'a> {
    pub fn new(value: &'a [u8]) -> Self {
        TlvZipIter {
            iter: TlvIter::new(value).into_iter(),
        }
    }
    pub fn from_vec(value: Vec<u8>) -> Self {
        TlvZipIter {
            iter: TlvIter::from_vec(value).into_iter(),
        }
    }

    pub fn from_tlv_iter(value: TlvIter<'a>) -> Self {
        TlvZipIter { iter: value }
    }
}

impl Iterator for TlvZipIter<'_> {
    type Item = (Tlv, Tlv);
    fn next(&mut self) -> Option<Self::Item> {
        Some((self.iter.next()?, self.iter.next()?))
    }
}

#[derive(Copy, Clone)]
pub struct TlvIter<'a> {
    buf: &'a [u8],
}

impl<'a> TlvIter<'a> {
    pub fn new(value: &'a [u8]) -> Self {
        TlvIter { buf: value }
    }
    pub fn from_vec(value: Vec<u8>) -> Self {
        TlvIter { buf: value.leak() }
    }
}

impl Iterator for TlvIter<'_> {
    type Item = Tlv;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let (r, remaining) = Tlv::parse(self.buf);
        self.buf = remaining;
        r.ok()
    }
}

pub fn tlv_to_lists(data: Vec<u8>) -> HashMap<u8, Vec<Vec<u8>>> {
    let mut parsed_manual: HashMap<u8, Vec<Vec<u8>>> = HashMap::new();
    for res in TlvIter::from_vec(data) {
        parsed_manual
            .entry(res.tag().into())
            .or_default()
            .push(res.value().to_vec());
    }
    parsed_manual
}
