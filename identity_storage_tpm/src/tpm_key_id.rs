use std::{fmt::Display, ops::Deref};
use identity_storage::KeyId;
use tss_esapi::handles::{KeyHandle, ObjectHandle};

use crate::error::TpmStorageError;

/// Custom struct to convert Tpm handle to [`KeyId`]
#[derive(Debug, PartialEq, Clone)]
pub struct TpmKeyId(u32);

impl Display for TpmKeyId{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:X}", self.0))
    }
}
impl From<u32> for TpmKeyId{
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl Into<String> for TpmKeyId{
    fn into(self) -> String {
        format!("{:X}", self.0)
    }
}

impl TryFrom<&str> for TpmKeyId {
    type Error = TpmStorageError;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let hex_value = value.trim_start_matches("0x");
        let dec_value = u32::from_str_radix(hex_value, 16)
        .map_err(|_|{TpmStorageError::BadAddressError(value.to_owned())})?;
        Ok(Self(dec_value))
    }
}

impl From<TpmKeyId> for KeyHandle{
    fn from(value: TpmKeyId) -> Self {
        KeyHandle::from(value.0)
    }
}

impl From<TpmKeyId> for KeyId{
    fn from(value: TpmKeyId) -> Self {
        KeyId::new(value)
    }
}

impl From<TpmKeyId> for ObjectHandle{
    fn from(value: TpmKeyId) -> Self {
        ObjectHandle::from(value.0)
    }
}

impl From<ObjectHandle> for TpmKeyId{
    fn from(value: ObjectHandle) -> Self {
        Self(value.value())
    }
}


impl Deref for TpmKeyId{
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TpmKeyId {
    pub fn value(&self) -> u32{
        self.0
    }
}
