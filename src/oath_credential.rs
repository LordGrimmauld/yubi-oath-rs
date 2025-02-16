use std::{
    cmp::Ordering,
    hash::{Hash, Hasher},
};

use crate::CredentialIDData;

#[derive(Debug, Clone)]
pub struct OathCredential {
    device_id: String,
    id_data: CredentialIDData,
    touch_required: bool,
}

impl OathCredential {
    pub fn new(name: &str, id_data: CredentialIDData, touch_required: bool) -> Self {
        Self {
            device_id: name.to_owned(),
            id_data,
            touch_required,
        }
    }
    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn id_data(&self) -> &CredentialIDData {
        &self.id_data
    }

    pub fn is_touch_required(&self) -> bool {
        self.touch_required
    }
}

impl PartialOrd for OathCredential {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let a = (
            self.id_data
                .issuer()
                .unwrap_or_else(|| self.id_data.name())
                .to_lowercase(),
            self.id_data.name().to_lowercase(),
        );
        let b = (
            other
                .id_data
                .issuer()
                .unwrap_or_else(|| other.id_data.name())
                .to_lowercase(),
            other.id_data.name().to_lowercase(),
        );
        Some(a.cmp(&b))
    }
}

impl PartialEq for OathCredential {
    fn eq(&self, other: &Self) -> bool {
        self.device_id == other.device_id && self.id_data == other.id_data
    }
}

impl Hash for OathCredential {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.device_id.hash(state);
        self.id_data.hash(state);
    }
}
