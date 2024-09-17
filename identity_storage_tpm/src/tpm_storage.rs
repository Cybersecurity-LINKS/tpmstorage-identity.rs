use std::sync::{Arc, Mutex};

use identity_jose::jws::JwsAlgorithm;
use identity_storage::{KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};
use tss_esapi::{constants::StartupType, handles::TpmHandle, structures::CapabilityData, tcti_ldr::NetworkTPMConfig, Context, Tcti};
use anyhow::{anyhow, Result};

/// Supported key types for TPM Storage
#[derive(Debug)]
enum TpmKeyType{
    P256,
}

impl std::fmt::Display for TpmKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            TpmKeyType::P256 => "P-256"
        };
        f.write_str(name)
    }
}

impl TryFrom<&KeyType> for TpmKeyType{
    type Error = KeyStorageError;

    fn try_from(value: &KeyType) -> Result<Self, Self::Error> {
        match value.as_str() {
            "P-256" => Ok(TpmKeyType::P256),
            _ => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType))
        }
    }
}

/// Storage implementation that uses the TPM for securely storing JWKs.
pub struct TpmStorage{
    ctx: Arc<Mutex<Context>>
}


const HANDLE_STORAGE_FIRST_INDEX:u32 = 0x81008000;
const HANDLE_STORAGE_LAST_INDEX:u32 = 0x8100FFFF;
impl TpmStorage {
    pub fn new() -> Result<TpmStorage>{
        let location = Tcti::Mssim(NetworkTPMConfig::default()); //TODO: rimuovere
        let mut ctx = Context::new(location)?;
        let _ =ctx.startup(StartupType::Clear)?; // TODO: rimuovere
        Ok(TpmStorage{ctx: Arc::new(Mutex::new(ctx))})
    }
    
    fn match_kty_with_alg(key_type: &TpmKeyType, alg: &JwsAlgorithm) -> KeyStorageResult<()>{
        match (key_type, alg) {
            (TpmKeyType::P256, JwsAlgorithm::ES256) => Ok(()),
            _ => Err(KeyStorageError::new(
                KeyStorageErrorKind::KeyAlgorithmMismatch
            ).with_custom_message(format!("Cannot use keytype {key_type} with algorithm {alg}")))
        }
    }

    /// This function returns an handle address that can be used for persistent storage in the Owner Hierarchy.
    /// The return value is the first empty handler starting from `HANDLE_STORAGE_FIRST_INDEX`
    pub fn get_free_handle(&self) -> Result<u32>{
        let mut ctx = match self.ctx.lock(){
            Ok(ctx) => ctx,
            Err(e) => return Err(anyhow!("Cannot retrieve the TPM device"))
        };
        
        // init reading loop of handles
        let mut more_data = true;
        let mut handles = vec![];
        while more_data {
            let cap_data;
            (cap_data, more_data) = ctx.get_capability(tss_esapi::constants::CapabilityType::Handles, HANDLE_STORAGE_FIRST_INDEX, HANDLE_STORAGE_LAST_INDEX)?;
            let handle_list = match cap_data {
                CapabilityData::Handles(list) => list,
                _ => return Err(anyhow!("Unexpected result from TPM"))
            };
            let filtered = handle_list.iter().filter_map(|handle| match handle{
                TpmHandle::Persistent(h) => Some(h),
                _ => None
            }).map(|persistent| {u32::from(*persistent)});

            handles.extend(filtered);
        }

        // Finding the first handle not in the list, starting from the first index.
        let free_handle = match (HANDLE_STORAGE_FIRST_INDEX..=HANDLE_STORAGE_LAST_INDEX)
        .find(|address| {!handles.contains(address)}){
            Some(handle) => handle,
            None => return Err(anyhow!("The persistent storage is full!"))
        };

        Ok(free_handle)
    }

}