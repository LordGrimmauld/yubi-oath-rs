//! # Rust bindings to the Oath application on the YubiKey
//!
//! Bindings closely resemble the reverse-engineered [python library](https://github.com/Yubico/yubikey-manager/blob/main/yubikit/oath.py),
//! as well as the discontinued crate [ykoath](https://crates.io/crates/ykoath)
//!

/// constants relevant for apdu, pcsc, error handling
pub mod constants;

/// OathCredential stores one credential
pub mod oath_credential;

/// OathCredentialId stores information about issuer, credential name, time raster, display
pub mod oath_credential_id;

mod refreshable_oath_credential;
mod transaction;

use constants::*;
use oath_credential::*;
use oath_credential_id::*;
use refreshable_oath_credential::*;
use transaction::*;

use std::time::{Duration, SystemTime};

use hmac::{Hmac, Mac};

fn hmac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(key).expect("Invalid key length");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hmac_shorten_key(key: &[u8], algo: HashAlgo) -> Vec<u8> {
    if key.len() > algo.digest_size() {
        algo.get_hash_fun()(key)
    } else {
        key.to_vec()
    }
}

fn time_challenge(timestamp: Option<SystemTime>, period: Duration) -> [u8; 8] {
    (timestamp
        .unwrap_or_else(SystemTime::now)
        .duration_since(SystemTime::UNIX_EPOCH)
        .as_ref()
        .map_or(0, Duration::as_secs)
        / period.as_secs())
    .to_be_bytes()
}

/// keeps track of transactions with a named YubiKey
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

    fn is_at_least_version(&self, minimum_version: Vec<u8>) -> bool {
        for (local, compare) in self.version.iter().zip(minimum_version) {
            if *local < compare {
                return false;
            }
        }
        true
    }

    pub fn require_version(&self, version: Vec<u8>) -> Result<(), Error> {
        if !self.is_at_least_version(version.to_owned()) {
            return Err(Error::Version(self.version.clone(), version));
        }
        Ok(())
    }

    pub fn unlock_session(&mut self, key: &[u8]) -> Result<(), Error> {
        let chal = match self.challenge.to_owned() {
            Some(chal) => chal,
            None => return Ok(()),
        };

        let hmac = hmac_sha1(key, &chal);
        let random_chal = getrandom::u64()?.to_be_bytes();
        let data = &[
            to_tlv(Tag::Response, &hmac),
            to_tlv(Tag::Challenge, &random_chal),
        ]
        .concat();
        let resp =
            self.transaction_context
                .apdu(0, Instruction::Validate as u8, 0, 0, Some(data))?;
        let verification = hmac_sha1(key, &random_chal);
        if tlv_to_map(resp.buf)
            .get(&(Tag::Response as u8))
            .map(|v| *v == verification)
            .unwrap_or(false)
        {
            self.locked = false;
            Ok(())
        } else {
            Err(Error::Unknown(
                "Unlocking session failed unexpectedly".to_string(),
            ))
        }
    }

    pub fn set_key(&mut self, key: &[u8]) -> Result<(), Error> {
        let random_chal = getrandom::u64()?.to_be_bytes();
        let hmac = hmac_sha1(key, &random_chal);
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
        self.require_version(vec![5, 3, 1])?;
        self.transaction_context.apdu(
            0,
            Instruction::Rename as u8,
            0,
            0,
            Some(&[old.as_tlv(), new.as_tlv()].concat()),
        )?;
        Ok(new)
    }

    pub fn delete_code(&self, cred: OathCredential) -> Result<(), Error> {
        self.transaction_context.apdu(
            0,
            Instruction::Delete as u8,
            0,
            0,
            Some(&cred.id_data.as_tlv()),
        )?;
        Ok(())
    }

    pub fn put_credential(
        &self,
        cred: OathCredential,
        secret: &[u8],
        algo: HashAlgo,
        digits: u8,
        counter: Option<u32>,
    ) -> Result<(), Error> {
        let secret_short = hmac_shorten_key(secret, algo);
        let mut secret_padded = [0u8; HMAC_MINIMUM_KEY_SIZE];
        let len_to_copy = secret_short.len().min(HMAC_MINIMUM_KEY_SIZE); // Avoid copying more than 14
        secret_padded[(HMAC_MINIMUM_KEY_SIZE - len_to_copy)..]
            .copy_from_slice(&secret_short[..len_to_copy]);

        let mut data = [
            cred.id_data.as_tlv(),
            to_tlv(
                Tag::Key,
                &[
                    [(cred.id_data.oath_type as u8) | (algo as u8), digits].to_vec(),
                    secret_padded.to_vec(),
                ]
                .concat(),
            ),
        ]
        .concat();

        if cred.touch_required {
            data.extend([Tag::Property as u8, 2u8]); // FIXME: python impl does *not* send this to tlv, which seems to work but feels wrong. See also: https://github.com/Yubico/yubikey-manager/issues/660
        }

        if let Some(c) = counter {
            data.extend(to_tlv(Tag::Imf, &c.to_be_bytes()));
        }

        self.transaction_context
            .apdu(0, Instruction::Put as u8, 0, 0, Some(&data))?;
        Ok(())
    }

    pub fn derive_key(&self, passphrase: &str) -> Vec<u8> {
        pbkdf2::pbkdf2_hmac_array::<sha1::Sha1, 16>(passphrase.as_bytes(), &self.salt, 1000)
            .to_vec()
    }

    pub fn calculate_refreshable_code(
        &self,
        cred: &OathCredential,
        timestamp_sys: Option<SystemTime>,
    ) -> Result<RefreshableOathCredential, Error> {
        let timestamp = timestamp_sys.unwrap_or_else(SystemTime::now);
        let code = self.calculate_code(cred, timestamp_sys)?;
        let mut refreshable_cred = RefreshableOathCredential::new(cred.to_owned(), self);
        refreshable_cred.force_update(Some(code), timestamp);

        Ok(refreshable_cred)
    }

    pub fn calculate_code(
        &self,
        cred: &OathCredential,
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
                &time_challenge(Some(timestamp), cred.id_data.get_period()),
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
                &time_challenge(Some(timestamp), DEFAULT_PERIOD),
            )),
        );

        let mut key_buffer = Vec::new();

        for (cred_id, meta) in TlvZipIter::from_vec(response?) {
            let touch = Into::<u8>::into(meta.tag()) == (Tag::Touch as u8); // touch only works with totp, this is intended
            let id_data = CredentialIDData::from_tlv(cred_id.value(), meta.tag());
            let code = OathCodeDisplay::from_tlv(meta);

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
            let oath_type = if (cred_id.value()[0] & 0xf0) == (Tag::Hotp as u8) {
                OathType::Hotp
            } else {
                OathType::Totp
            };

            let id_data = CredentialIDData::from_bytes(&cred_id.value()[1..], oath_type);
            key_buffer.push(id_data);
        }

        Ok(key_buffer)
    }
}
