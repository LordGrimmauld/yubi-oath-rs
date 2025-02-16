use std::{
    fmt::Display,
    ops::Range,
    time::{Duration, SystemTime},
};

use crate::{OathCodeDisplay, OathCredential, OathSession, OathType};

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
            .calculate_code(&self.cred, Some(timestamp))
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
                let time_step = timestamp_seconds / (self.cred.id_data.get_period().as_secs());
                let valid_from = SystemTime::UNIX_EPOCH
                    .checked_add(
                        self.cred
                            .id_data
                            .get_period()
                            .saturating_mul(time_step as u32),
                    )
                    .unwrap();
                let valid_to = valid_from
                    .checked_add(self.cred.id_data.get_period())
                    .unwrap();
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
