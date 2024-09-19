use std::sync::{Arc, Mutex};

use identity_jose::jws::JwsAlgorithm;
use identity_storage::{KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};
use tss_esapi::{abstraction::public, attributes::{self, ObjectAttributes}, constants::{SessionType, StartupType}, handles::{KeyHandle, ObjectHandle, TpmHandle}, interface_types::{algorithm::{HashingAlgorithm, PublicAlgorithm}, ecc::EccCurve, resource_handles::Hierarchy, session_handles::AuthSession}, structures::{CapabilityData, CreatePrimaryKeyResult, Digest, EccScheme, HashScheme, KeyDerivationFunctionScheme, KeyedHashScheme, Private, Public, PublicBuilder, PublicEccParameters, PublicEccParametersBuilder, PublicKeyedHashParameters, SymmetricDefinition}, tcti_ldr::{DeviceConfig, NetworkTPMConfig}, Context, Tcti};
use anyhow::{anyhow, Result};

use crate::error::TpmStorageError;

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
    pub (crate) ctx: Arc<Mutex<Context>>,
    pub (crate) primary: Arc<KeyHandle>,
    pub (crate) session: Arc<Option<AuthSession>>
}

const HANDLE_STORAGE_FIRST_INDEX:u32 = 0x81008000;
const HANDLE_STORAGE_LAST_INDEX:u32 = 0x8100FFFF;
impl TpmStorage {
    pub fn new() -> Result<TpmStorage>{
        let location = Tcti::Device(DeviceConfig::default());
        let mut ctx = Context::new(location)?;
        // Generate an Auth Session for TPM communication.
        let auth_session = ctx.start_auth_session(None, None, None, 
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256)?;

        let storage_primary = ctx.execute_with_session(auth_session, |context| {
            let object_attributes = ObjectAttributes::builder()
                .with_fixed_parent(true)
                .with_fixed_tpm(true)
                .with_restricted(true)
                .with_user_with_auth(true)
                .with_sensitive_data_origin(true)
                .with_sign_encrypt(true)
                .build()?;

            let public = PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::KeyedHash)
                .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::HMAC_SHA_256))
                .with_keyed_hash_unique_identifier(Digest::default())
                .with_object_attributes(object_attributes)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .build()?;
            context.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })?;

        Ok(TpmStorage{ctx: Arc::new(Mutex::new(ctx)), primary: Arc::new(storage_primary.key_handle.clone()), session: Arc::new(auth_session)})
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
    pub (crate) fn get_free_handle(&self) -> Result<u32>{
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

    pub (crate) fn create_signing_key(&self) -> Result<(Private, Public)>{
        let ctx = match self.ctx.lock(){
            Ok(ctx) => ctx,
            Err(_) => return Err(TpmStorageError::DeviceUnavailableError.into())
        };

        let attributes = ObjectAttributes::new_fixed_signing_key();
        let ecc_parameters = PublicEccParametersBuilder::new()
            .with_curve(EccCurve::NistP256)
            .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
            .with_is_signing_key(true)
            .build()?;

        todo!()

    }
}


#[cfg(test)]
mod tests {
    use testcontainers::{core::{WaitFor,IntoContainerPort}, GenericImage, runners::AsyncRunner};
    use super::*;

    impl TpmStorage {
        fn new_test_instance() -> Result<TpmStorage> {
                let location = Tcti::Mssim(NetworkTPMConfig::default());
                let mut ctx = Context::new(location)?;
                // Generate an Auth Session for TPM communication.
                let auth_session = ctx.start_auth_session(None, None, None, 
                    SessionType::Hmac,
                    SymmetricDefinition::AES_128_CFB,
                    HashingAlgorithm::Sha256)?;
        
                let storage_primary = ctx.execute_with_session(auth_session, |context| {
                    let object_attributes = ObjectAttributes::builder()
                        .with_fixed_parent(true)
                        .with_fixed_tpm(true)
                        .with_restricted(true)
                        .with_user_with_auth(true)
                        .with_sensitive_data_origin(true)
                        .with_sign_encrypt(true)
                        .build()?;
        
                    let public = PublicBuilder::new()
                        .with_public_algorithm(PublicAlgorithm::KeyedHash)
                        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::HMAC_SHA_256))
                        .with_keyed_hash_unique_identifier(Digest::default())
                        .with_object_attributes(object_attributes)
                        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                        .build()?;
                    context.create_primary(Hierarchy::Owner, public, None, None, None, None)
                })?;
                Ok(TpmStorage{ctx: Arc::new(Mutex::new(ctx)), primary: Arc::new(storage_primary.key_handle.clone()), session: Arc::new(auth_session)})
        }
    }

    #[tokio::test]
    async fn create_key() -> Result<(), anyhow::Error>{

        let _ = GenericImage::new("my_tpm_server", "latest")
        .with_exposed_port(2321.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Platform server listening on port 2322"))
        .start().await?;

        let tpm = TpmStorage::new_test_instance()?;

        assert!(true);
        Ok(())
    }
}