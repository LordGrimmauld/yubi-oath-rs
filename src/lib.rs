mod constants;
use constants::*;
mod transaction;
use transaction::*;
mod oath_credential;
mod oath_credentialid;
/// Utilities for interacting with YubiKey OATH/TOTP functionality
use std::{fmt::Display, time::Duration, time::SystemTime};

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use oath_credential::*;
use oath_credentialid::*;

fn _get_device_id(salt: Vec<u8>) -> String {
    let result = HashAlgo::Sha256.get_hash_fun()(salt.leak());

    // Get the first 16 bytes of the hash
    let hash_16_bytes = &result[..16];

    // Base64 encode the result and remove padding ('=')
    return general_purpose::URL_SAFE_NO_PAD.encode(hash_16_bytes);
}
fn _hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("Invalid key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn _derive_key(salt: &[u8], passphrase: &str) -> Vec<u8> {
    pbkdf2::pbkdf2_hmac_array::<sha1::Sha1, 16>(passphrase.as_bytes(), salt, 1000).to_vec()
}

fn _hmac_shorten_key(key: &[u8], algo: HashAlgo) -> Vec<u8> {
    if key.len() > algo.digest_size() {
        algo.get_hash_fun()(key)
    } else {
        key.to_vec()
    }
}

fn _get_challenge(timestamp: u64, period: u64) -> [u8; 8] {
    return ((timestamp / period) as u64).to_be_bytes();
}

fn time_to_u64(timestamp: SystemTime) -> u64 {
    timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .as_ref()
        .map_or(0, Duration::as_secs)
}
pub struct OathSession<'a> {
    version: &'a [u8],
    salt: &'a [u8],
    challenge: &'a [u8],
    transaction_context: TransactionContext,
    pub name: String,
}

fn clone_with_lifetime<'a>(data: &'a [u8]) -> Vec<u8> {
    // Clone the slice into a new Vec<u8>
    data.to_vec() // `to_vec()` will return a Vec<u8> that has its own ownership
}

pub struct RefreshableOathCredential<'a> {
    pub cred: OathCredential,
    pub code: Option<OathCodeDisplay>,
    pub valid_from: u64,
    pub valid_to: u64,
    refresh_provider: &'a OathSession<'a>,
}

impl<'a> Display for RefreshableOathCredential<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(c) = self.code {
            f.write_fmt(format_args!("{}: {}", self.cred.id_data, c))
        } else {
            f.write_fmt(format_args!("{}", self.cred.id_data))
        }
    }
}

impl<'a> RefreshableOathCredential<'a> {
    pub fn new(cred: OathCredential, refresh_provider: &'a OathSession<'a>) -> Self {
        RefreshableOathCredential {
            cred,
            code: None,
            valid_from: 0,
            valid_to: 0,
            refresh_provider,
        }
    }

    pub fn force_update(&mut self, code: Option<OathCodeDisplay>, timestamp: SystemTime) {
        self.code = code;
        (self.valid_from, self.valid_to) =
            RefreshableOathCredential::format_validity_time_frame(&self, timestamp);
    }

    pub fn refresh(&mut self) {
        let timestamp = SystemTime::now();
        let refresh_result = self
            .refresh_provider
            .calculate_code(self.cred.to_owned(), Some(timestamp))
            .ok();
        self.force_update(refresh_result, timestamp);
    }

    pub fn get_or_refresh(mut self) -> RefreshableOathCredential<'a> {
        if !self.is_valid() {
            self.refresh();
        }
        return self;
    }

    pub fn is_valid(&self) -> bool {
        let current_time = time_to_u64(SystemTime::now());
        self.valid_from <= current_time && current_time <= self.valid_to
    }

    fn format_validity_time_frame(&self, timestamp: SystemTime) -> (u64, u64) {
        let timestamp_seconds = time_to_u64(timestamp);
        match self.cred.id_data.oath_type {
            OathType::Totp => {
                let time_step = timestamp_seconds / (self.cred.id_data.period as u64);
                let valid_from = time_step * (self.cred.id_data.period as u64);
                let valid_to = (time_step + 1) * (self.cred.id_data.period as u64);
                (valid_from, valid_to)
            }
            OathType::Hotp => (timestamp_seconds, 0x7FFFFFFFFFFFFFFF),
        }
    }
}

impl<'a> OathSession<'a> {
    pub fn new(name: &str) -> Result<Self, Error> {
        let transaction_context = TransactionContext::from_name(name)?;
        let info_buffer =
            transaction_context.apdu_read_all(0, INS_SELECT, 0x04, 0, Some(&OATH_AID))?;

        let info_map = tlv_to_map(info_buffer);
        for (tag, data) in &info_map {
            // Printing tag and data
            println!("{:?}: {:?}", tag, data);
        }

        Ok(Self {
            version: clone_with_lifetime(
                info_map.get(&(Tag::Version as u8)).unwrap_or(&vec![0u8; 0]),
            )
            .leak(),
            salt: clone_with_lifetime(info_map.get(&(Tag::Name as u8)).unwrap_or(&vec![0u8; 0]))
                .leak(),
            challenge: clone_with_lifetime(
                info_map
                    .get(&(Tag::Challenge as u8))
                    .unwrap_or(&vec![0u8; 0]),
            )
            .leak(),
            name: name.to_string(),
            transaction_context,
        })
    }

    pub fn get_version(&self) -> &[u8] {
        self.version
    }

    pub fn delete_code(&self, cred: OathCredential) -> Result<ApduResponse, Error> {
        self.transaction_context.apdu(
            0,
            Instruction::Delete as u8,
            0,
            0,
            Some(&to_tlv(Tag::Name, &cred.id_data.format_cred_id())),
        )
    }

    pub fn calculate_code(
        &self,
        cred: OathCredential,
        timestamp_sys: Option<SystemTime>,
    ) -> Result<OathCodeDisplay, Error> {
        if self.name != cred.device_id {
            return Err(Error::DeviceMismatchError);
        }

        let timestamp = time_to_u64(timestamp_sys.unwrap_or_else(SystemTime::now));

        let mut data = to_tlv(Tag::Name, &cred.id_data.format_cred_id());
        if cred.id_data.oath_type == OathType::Totp {
            data.extend(to_tlv(
                Tag::Challenge,
                &_get_challenge(timestamp, cred.id_data.period as u64),
            ));
        }

        let resp = self.transaction_context.apdu_read_all(
            0,
            Instruction::Calculate as u8,
            0,
            0x01,
            Some(&data),
        );

        let meta = TlvIter::from_vec(resp?).next().ok_or(Error::ParsingError(
            "No credentials to unpack found in response".to_string(),
        ))?;

        OathCodeDisplay::from_tlv(meta).ok_or(Error::ParsingError(
            "error parsing calculation response".to_string(),
        ))
    }

    /// Read the OATH codes from the device, calculate TOTP codes that don't
    /// need touch
    pub fn calculate_oath_codes(&self) -> Result<Vec<RefreshableOathCredential>, Error> {
        let timestamp = SystemTime::now();
        // Request OATH codes from device
        let response = self.transaction_context.apdu_read_all(
            0,
            Instruction::CalculateAll as u8,
            0,
            0x01,
            Some(&to_tlv(Tag::Challenge, &time_challenge(Some(timestamp)))),
        );

        let mut key_buffer = Vec::new();

        for (cred_id, meta) in TlvZipIter::from_vec(response?) {
            let touch = Into::<u8>::into(meta.tag()) == (Tag::Touch as u8); // touch only works with totp, this is intended
            let id_data = CredentialIDData::from_tlv(cred_id.value(), meta.tag());
            let code = OathCodeDisplay::from_tlv(meta);

            // println!("id bytes: {:?}", cred_id.value());
            // println!("id recon: {:?}", id_data.format_cred_id());

            let cred = OathCredential {
                device_id: self.name.clone(),
                id_data,
                touch_required: touch,
            };

            let mut refreshable_cred = RefreshableOathCredential::new(cred, self);
            refreshable_cred.force_update(code, timestamp);

            key_buffer.push(refreshable_cred);
        }

        return Ok(key_buffer);
    }
    pub fn list_oath_codes(&self) -> Result<Vec<CredentialIDData>, Error> {
        // Request OATH codes from device
        let response =
            self.transaction_context
                .apdu_read_all(0, Instruction::List as u8, 0, 0, None);

        let mut key_buffer = Vec::new();

        for cred_id in TlvIter::from_vec(response?) {
            let id_data = CredentialIDData::from_bytes(
                &cred_id.value()[1..],
                *cred_id.value().get(0).unwrap_or(&0u8) & 0xf0,
            );
            key_buffer.push(id_data);
        }

        return Ok(key_buffer);
    }
}

fn time_challenge(timestamp: Option<SystemTime>) -> [u8; 8] {
    (time_to_u64(timestamp.unwrap_or_else(SystemTime::now)) / 30).to_be_bytes()
}
