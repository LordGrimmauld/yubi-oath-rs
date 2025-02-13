use std::{collections::HashMap, ffi::CString, fmt::Display};

use apdu_core::{Command, Response};
use iso7816_tlv::simple::{Tag as TlvTag, Tlv};
use ouroboros::self_referencing;
use pcsc::{Card, Transaction};

use crate::{ErrorResponse, Instruction, SuccessResponse, Tag};

#[derive(PartialEq, Eq, Debug)]
pub enum FormattableErrorResponse {
    NoError,
    Unknown(String),
    Protocol(ErrorResponse),
    PcscError(pcsc::Error),
    ParsingError(String),
    DeviceMismatchError,
}

impl FormattableErrorResponse {
    pub fn from_apdu_response(sw1: u8, sw2: u8) -> FormattableErrorResponse {
        let code: u16 = (sw1 as u16 | sw2 as u16) << 8;
        if let Some(e) = ErrorResponse::any_match(code) {
            return FormattableErrorResponse::Protocol(e);
        }
        if SuccessResponse::any_match(code)
            .or(SuccessResponse::any_match(sw1.into()))
            .is_some()
        {
            return FormattableErrorResponse::NoError;
        }
        FormattableErrorResponse::Unknown(String::from("Unknown error"))
    }
    pub fn is_ok(&self) -> bool {
        *self == FormattableErrorResponse::NoError
    }
    pub fn as_opt(self) -> Option<FormattableErrorResponse> {
        if self.is_ok() {
            None
        } else {
            Some(self)
        }
    }

    fn from_transmit(err: pcsc::Error) -> FormattableErrorResponse {
        FormattableErrorResponse::PcscError(err)
    }

    fn as_string(&self) -> String {
        match self {
            FormattableErrorResponse::NoError => "ok".to_string(),
            FormattableErrorResponse::Unknown(msg) => msg.to_owned(),
            FormattableErrorResponse::Protocol(error_response) => error_response.as_string(),
            FormattableErrorResponse::PcscError(error) => format!("{}", error),
            FormattableErrorResponse::ParsingError(msg) => msg.to_owned(),
            FormattableErrorResponse::DeviceMismatchError => "Devices do not match".to_string(),
        }
    }
}

impl Display for FormattableErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.as_string())
    }
}

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
) -> Result<ApduResponse, FormattableErrorResponse> {
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
        // Err(err) => return Err(format!("{}", err)),
        Err(err) => return Err(FormattableErrorResponse::from_transmit(err)),
    };

    let resp = Response::from(rx_buf);
    let error_context =
        FormattableErrorResponse::from_apdu_response(resp.trailer.0, resp.trailer.1);

    if !error_context.is_ok() {
        return Err(error_context);
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
) -> Result<Vec<u8>, FormattableErrorResponse> {
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
    ) -> Result<ApduResponse, FormattableErrorResponse> {
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
    ) -> Result<Vec<u8>, FormattableErrorResponse> {
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
    return parsed_manual;
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

impl<'a> Iterator for TlvZipIter<'a> {
    type Item = (Tlv, Tlv);
    fn next(&mut self) -> Option<Self::Item> {
        return Some((self.iter.next()?, self.iter.next()?));
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

impl<'a> Iterator for TlvIter<'a> {
    type Item = Tlv;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let (r, remaining) = Tlv::parse(self.buf);
        self.buf = remaining;
        return r.ok();
    }
}

pub fn tlv_to_lists(data: Vec<u8>) -> HashMap<u8, Vec<Vec<u8>>> {
    let mut parsed_manual: HashMap<u8, Vec<Vec<u8>>> = HashMap::new();
    for res in TlvIter::from_vec(data) {
        parsed_manual
            .entry(res.tag().into())
            .or_insert_with(Vec::new)
            .push(res.value().to_vec());
    }
    return parsed_manual;
}
