#![allow(unused)]
mod constants;
use constants::*;
mod transaction;
use transaction::*;
mod oath_credential;
mod oath_credentialid;
/// Utilities for interacting with YubiKey OATH/TOTP functionality
use std::{
    fmt::Display,
    ops::{Range, RangeInclusive},
    time::{Duration, Instant, SystemTime},
};

use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use oath_credential::*;
use oath_credentialid::*;

fn _get_device_id(salt: Vec<u8>) -> String {
    let result = HashAlgo::Sha256.get_hash_fun()(salt.leak());

    // Get the first 16 bytes of the hash
    let hash_16_bytes = &result[..16];

    // Base64 encode the result and remove padding ('=')
    general_purpose::URL_SAFE_NO_PAD.encode(hash_16_bytes)
}
fn _hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("Invalid key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn _hmac_shorten_key(key: &[u8], algo: HashAlgo) -> Vec<u8> {
    if key.len() > algo.digest_size() {
        algo.get_hash_fun()(key)
    } else {
        key.to_vec()
    }
}

pub struct RefreshableOathCredential<'a> {
    pub cred: OathCredential,
    pub code: Option<OathCodeDisplay>,
    pub valid_timeframe: Range<SystemTime>,
    refresh_provider: &'a OathSession,
}

impl Display for RefreshableOathCredential<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(c) = self.code {
            f.write_fmt(format_args!("{}: {}", self.cred.id_data, c))
        } else {
            f.write_fmt(format_args!("{}", self.cred.id_data))
        }
    }
}

impl<'a> RefreshableOathCredential<'a> {
    pub fn new(cred: OathCredential, refresh_provider: &'a OathSession) -> Self {
        RefreshableOathCredential {
            cred,
            code: None,
            valid_timeframe: SystemTime::UNIX_EPOCH..SystemTime::UNIX_EPOCH,
            refresh_provider,
        }
    }

    pub fn force_update(&mut self, code: Option<OathCodeDisplay>, timestamp: SystemTime) {
        self.code = code;
        self.valid_timeframe =
            RefreshableOathCredential::format_validity_time_frame(self, timestamp);
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
        self
    }

    pub fn is_valid(&self) -> bool {
        self.valid_timeframe.contains(&SystemTime::now())
    }

    fn format_validity_time_frame(&self, timestamp: SystemTime) -> Range<SystemTime> {
        match self.cred.id_data.oath_type {
            OathType::Totp => {
                let timestamp_seconds = timestamp
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .as_ref()
                    .map_or(0, Duration::as_secs);
                let time_step = timestamp_seconds / (self.cred.id_data.period.as_secs());
                let valid_from = SystemTime::UNIX_EPOCH
                    .checked_add(self.cred.id_data.period.saturating_mul(time_step as u32))
                    .unwrap();
                // time_step * (self.cred.id_data.period.as_secs());
                let valid_to = valid_from.checked_add(self.cred.id_data.period).unwrap();
                valid_from..valid_to
            }
            OathType::Hotp => {
                timestamp
                    ..SystemTime::UNIX_EPOCH
                        .checked_add(Duration::from_secs(u64::MAX))
                        .unwrap()
            }
        }
    }
}

pub struct OathSession {
    version: Vec<u8>,
    salt: Vec<u8>,
    challenge: Option<Vec<u8>>,
    transaction_context: TransactionContext,
    pub locked: bool,
    pub name: String,
}

impl OathSession {
    pub fn new(name: &str) -> Result<Self, Error> {
        let transaction_context = TransactionContext::from_name(name)?;
        let info_buffer =
            transaction_context.apdu_read_all(0, INS_SELECT, 0x04, 0, Some(&OATH_AID))?;

        let info_map = tlv_to_map(info_buffer);
        for (tag, data) in &info_map {
            // Printing tag and data
            println!("{:?}: {:?}", tag, data);
        }

        let challenge = info_map.get(&(Tag::Challenge as u8)).map(Vec::to_owned);
        Ok(Self {
            locked: challenge.is_some(),
            version: info_map
                .get(&(Tag::Version as u8))
                .unwrap_or(&vec![0u8; 0])
                .to_owned(),
            salt: info_map
                .get(&(Tag::Name as u8))
                .unwrap_or(&vec![0u8; 0])
                .to_owned(),
            challenge,
            name: name.to_string(),
            transaction_context,
        })
    }

    pub fn get_version(&self) -> &[u8] {
        &self.version
    }

    pub fn unlock_session(&mut self, key: &[u8]) -> Result<(), Error> {
        let chal = match self.challenge.to_owned() {
            Some(chal) => chal,
            None => return Ok(()),
        };

        if !self.locked {
            return Ok(());
        }

        let hmac = _hmac_sha1(key, &chal);
        let random_chal = getrandom::u64().unwrap().to_be_bytes(); // FIXME: unwrap
        let data = &[
            to_tlv(Tag::Response, &hmac),
            to_tlv(Tag::Challenge, &random_chal),
        ]
        .concat();
        let resp =
            self.transaction_context
                .apdu(0, Instruction::Validate as u8, 0, 0, Some(data))?;
        let verification = _hmac_sha1(key, &random_chal);
        if tlv_to_map(resp.buf)
            .get(&(Tag::Response as u8))
            .map(|v| *v == verification)
            .unwrap_or(false)
        {
            self.locked = false;
            Ok(())
        } else {
            Err(Error::FailedAuthentication)
        }
    }

    pub fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        let random_chal = getrandom::u64().unwrap().to_be_bytes(); // FIXME: unwrap
        let hmac = _hmac_sha1(key, &random_chal);
        let data = &[
            to_tlv(
                Tag::Key,
                &[&[(OathType::Totp as u8) | (HashAlgo::Sha1 as u8); 1], key].concat(),
            ),
            to_tlv(Tag::Challenge, &random_chal),
            to_tlv(Tag::Response, &hmac),
        ]
        .concat();
        self.transaction_context
            .apdu(0, Instruction::SetCode as u8, 0, 0, Some(data))?;
        let info_buffer =
            self.transaction_context
                .apdu_read_all(0, INS_SELECT, 0x04, 0, Some(&OATH_AID))?;
        let info_map = tlv_to_map(info_buffer);
        self.challenge = info_map.get(&(Tag::Challenge as u8)).map(Vec::to_owned);
        self.locked = self.challenge.is_some();

        self.unlock_session(key)
    }

    pub fn unset_key(&mut self) -> Result<(), Error> {
        self.transaction_context.apdu(
            0,
            Instruction::SetCode as u8,
            0,
            0,
            Some(&to_tlv(Tag::Key, &[0u8; 0])),
        )?;
        self.locked = false;
        self.challenge = None;
        Ok(())
    }

    pub fn rename_credential(
        &self,
        old: CredentialIDData,
        new: CredentialIDData,
    ) -> Result<CredentialIDData, Error> {
        // require_version(self.version, (5, 3, 1)) TODO: version checking
        self.transaction_context.apdu(
            0,
            Instruction::Rename as u8,
            0,
            0,
            Some(&[old.as_tlv(), new.as_tlv()].concat()),
        )?;
        Ok(new)
    }

    pub fn delete_code(&self, cred: OathCredential) -> Result<ApduResponse, Error> {
        self.transaction_context.apdu(
            0,
            Instruction::Delete as u8,
            0,
            0,
            Some(&cred.id_data.as_tlv()),
        )
    }

    pub fn derive_key(&self, passphrase: &str) -> Vec<u8> {
        pbkdf2::pbkdf2_hmac_array::<sha1::Sha1, 16>(passphrase.as_bytes(), &self.salt, 1000)
            .to_vec()
    }

    pub fn calculate_code(
        &self,
        cred: OathCredential,
        timestamp_sys: Option<SystemTime>,
    ) -> Result<OathCodeDisplay, Error> {
        if self.name != cred.device_id {
            return Err(Error::DeviceMismatch);
        }

        let timestamp = timestamp_sys.unwrap_or_else(SystemTime::now);

        let mut data = cred.id_data.as_tlv();
        if cred.id_data.oath_type == OathType::Totp {
            data.extend(to_tlv(
                Tag::Challenge,
                &time_challenge(Some(timestamp), Some(cred.id_data.period)),
            ));
        }

        let resp = self.transaction_context.apdu_read_all(
            0,
            Instruction::Calculate as u8,
            0,
            0x01,
            Some(&data),
        );

        let meta = TlvIter::from_vec(resp?).next().ok_or(Error::Parsing(
            "No credentials to unpack found in response".to_string(),
        ))?;

        OathCodeDisplay::from_tlv(meta).ok_or(Error::Parsing(
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
            Some(&to_tlv(
                Tag::Challenge,
                &time_challenge(Some(timestamp), None),
            )),
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

        Ok(key_buffer)
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
                *cred_id.value().first().unwrap_or(&0u8) & 0xf0,
            );
            key_buffer.push(id_data);
        }

        Ok(key_buffer)
    }
}

fn time_challenge(timestamp: Option<SystemTime>, period: Option<Duration>) -> [u8; 8] {
    (timestamp
        .unwrap_or_else(SystemTime::now)
        .duration_since(SystemTime::UNIX_EPOCH)
        .as_ref()
        .map_or(0, Duration::as_secs)
        / period.unwrap_or(DEFAULT_PERIOD).as_secs())
    .to_be_bytes()
}
