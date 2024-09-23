use std::{io::Seek, ops::Deref, sync::{Arc, Mutex}};

use identity_jose::{jwk::{Jwk, JwkParamsEc}, jws::JwsAlgorithm, jwu};
use identity_storage::{KeyId, KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};
use tss_esapi::{abstraction::public, attributes::ObjectAttributes, constants::SessionType, handles::{KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle}, interface_types::{algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode}, dynamic_handles::Persistent, ecc::EccCurve, key_bits::AesKeyBits, resource_handles::{Hierarchy, Provision}, session_handles::AuthSession}, structures::{CapabilityData, CreateKeyResult, EccPoint, EccScheme, HashScheme, Public, PublicBuilder, PublicEccParameters, PublicEccParametersBuilder, SymmetricDefinition, SymmetricDefinitionObject}, tcti_ldr::DeviceConfig, traits::Marshall, tss2_esys::TPM2B_PUBLIC, utils::PublicKey, Context, Tcti};
use anyhow::{anyhow, Result};

use crate::error::TpmStorageError;

/// Supported key types for TPM Storage
#[derive(Debug)]
pub enum TpmKeyType{
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

/// Custom struct to convert Tpm handle to [`KeyId`]
#[derive(Debug, PartialEq, Clone)]
pub struct TpmKeyId(u32);

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

impl TryFrom<String> for TpmKeyId{
    type Error = TpmStorageError;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        let hex_value = value.trim_start_matches("0x");
        let dec_value = u32::from_str_radix(hex_value, 16)
        .map_err(|_|{TpmStorageError::BadAddressError(value)})?;
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

impl From<KeyHandle> for TpmKeyId{
    fn from(value: KeyHandle) -> Self {
        Self(value.value())
    }
}


impl Deref for TpmKeyId{
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
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
            let object_attributes = ObjectAttributes::new_fixed_parent_key();
            let parameters = PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::Aes{ key_bits: AesKeyBits::Aes128, mode: SymmetricMode::Cfb},
                EccCurve::NistP256
            ).build()?;
            let public = PublicBuilder::new()
                .with_ecc_parameters(parameters)
                .with_ecc_unique_identifier(EccPoint::default())
                .with_object_attributes(object_attributes)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .build()?;
            context.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })?;

        Ok(TpmStorage{ctx: Arc::new(Mutex::new(ctx)), primary: Arc::new(storage_primary.key_handle.clone()), session: Arc::new(auth_session)})
    }

    pub (crate) fn match_kty_with_alg(key_type: &TpmKeyType, alg: &JwsAlgorithm) -> KeyStorageResult<()>{
        match (key_type, alg) {
            (TpmKeyType::P256, JwsAlgorithm::ES256) => Ok(()),
            _ => Err(KeyStorageError::new(
                KeyStorageErrorKind::KeyAlgorithmMismatch
            ).with_custom_message(format!("Cannot use keytype {key_type} with algorithm {alg}")))
        }
    }

    /// This function returns an handle address that can be used for persistent storage in the Owner Hierarchy.
    /// The return value is the first empty handler starting from `HANDLE_STORAGE_FIRST_INDEX`
    pub (crate) fn get_free_handle(&self) -> Result<TpmKeyId>{
        let mut ctx = match self.ctx.lock(){
            Ok(ctx) => ctx,
            Err(_) => return Err(anyhow!("Cannot retrieve the TPM device"))
        };
        
        // init reading loop of handles
        let mut more_data = true;
        let mut handles = vec![];
        while more_data {
            let cap_data;
            (cap_data, more_data) = ctx.get_capability(tss_esapi::constants::CapabilityType::Handles,
                HANDLE_STORAGE_FIRST_INDEX.into(),
                HANDLE_STORAGE_LAST_INDEX.into())?;
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
        let free_handle:u32 = match (HANDLE_STORAGE_FIRST_INDEX..=HANDLE_STORAGE_LAST_INDEX)
        .find(|address| {!handles.contains(address)}){
            Some(handle) => handle,
            None => return Err(anyhow!("The persistent storage is full!"))
        };

        Ok(TpmKeyId::from(free_handle))
    }

    fn select_ecc_key_parameters(key_type: &TpmKeyType) -> Result<Public>{

        let (crv, hashing) = match key_type {
            TpmKeyType::P256 => (EccCurve::NistP256, HashingAlgorithm::Sha256),
            _ => return Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType).into())
        };

        let attributes = ObjectAttributes::new_fixed_signing_key();

        let ecc_parameters = PublicEccParametersBuilder::new_unrestricted_signing_key(
            EccScheme::EcDsa(HashScheme::new(hashing)),
            crv).build()?;
        let public = PublicBuilder::new()
        .with_ecc_parameters(ecc_parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .with_object_attributes(attributes)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .build()?;
        
        Ok(public)
    }
    
    /// Generate the correct [`Public`] structure starting from a [`TpmKeyType`]
    fn select_key_parameters(key_type: &TpmKeyType) -> Result<Public>{
        match key_type {
            TpmKeyType::P256 => Self::select_ecc_key_parameters(key_type),
            _ => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType).into())
        }
    }
    
    /// Create a key for signing operation protected in the TPM.
    pub (crate) fn create_signing_key(&self, key_type: &TpmKeyType) -> Result<(ObjectHandle, PublicKey)>{
        let mut ctx = match self.ctx.lock(){
            Ok(ctx) => ctx,
            Err(_) => return Err(TpmStorageError::DeviceUnavailableError.into())
        };

        let public = Self::select_key_parameters(key_type)?;
        ctx.execute_with_session(*self.session, |ctx| {
            let key = ctx.create(*self.primary, public, None, None, None, None)?;
            let load = ctx.load(*self.primary, key.out_private, key.out_public.clone())?;
            let public_key = PublicKey::try_from(key.out_public)?;
            Ok((load.into(), public_key))
        })
    }

    /// Add a TPM object in the persistent memory.
    pub (crate) fn store_key(&self, tmp_handle: ObjectHandle ,storage_handle: TpmKeyId)-> Result<TpmKeyId>{
        let mut ctx = match self.ctx.lock(){
            Ok(ctx) => ctx,
            Err(_) => return Err(TpmStorageError::DeviceUnavailableError.into())
        };

        let persistent_handle:PersistentTpmHandle = PersistentTpmHandle::new(*storage_handle)?;
        ctx.execute_with_session(*self.session, |context|{
            context.evict_control(Provision::Owner,
                tmp_handle,
                Persistent::Persistent(persistent_handle))
        })?;

        Ok(storage_handle.clone().into())
    }
    
    fn encode_ec_jwk(key_type: &TpmKeyType, x: impl AsRef<[u8]>, y: impl AsRef<[u8]>) -> Jwk{
        let mut params = JwkParamsEc::new();
        params.x = jwu::encode_b64(x);
        params.y = jwu::encode_b64(y);
        params.crv = key_type.to_string();
        Jwk::from_params(params)
    }
    pub (crate) fn encode_jwk(key_type: &TpmKeyType, public_key: PublicKey) -> Result<Jwk, KeyStorageError>{
        match (key_type, public_key){
            (TpmKeyType::P256, PublicKey::Ecc { x, y }) => Ok(Self::encode_ec_jwk(key_type, &x, &y)),
            _ => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType))
        }
    }
}


#[cfg(test)]
mod tests {
    use tss_esapi::{constants::StartupType, tcti_ldr::NetworkTPMConfig};

    use super::*;

    impl TpmStorage {
        fn new_test_instance() -> Result<TpmStorage> {
                let location = Tcti::Mssim(NetworkTPMConfig::default());
                let mut ctx = Context::new(location)?;
                // TPM Simulator startup
                let _ = ctx.startup(StartupType::Clear)?;
                // Generate an Auth Session for TPM communication.
                let auth_session = ctx.start_auth_session(None, None, None, 
                    SessionType::Hmac,
                    SymmetricDefinition::AES_128_CFB,
                    HashingAlgorithm::Sha256)?;
        
                let storage_primary = ctx.execute_with_session(auth_session, |context| {
                    let object_attributes = ObjectAttributes::new_fixed_parent_key();
                    let parameters = PublicEccParametersBuilder::new_restricted_decryption_key(
                        SymmetricDefinitionObject::Aes{ key_bits: AesKeyBits::Aes128, mode: SymmetricMode::Cfb},
                        EccCurve::NistP256
                    ).build()?;
                    let public = PublicBuilder::new()
                        .with_ecc_parameters(parameters)
                        .with_ecc_unique_identifier(EccPoint::default())
                        .with_object_attributes(object_attributes)
                        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                        .with_public_algorithm(PublicAlgorithm::Ecc)
                        .build()?;
                    context.create_primary(Hierarchy::Owner, public, None, None, None, None)
                })?;
                Ok(TpmStorage{ctx: Arc::new(Mutex::new(ctx)), primary: Arc::new(storage_primary.key_handle.clone()), session: Arc::new(auth_session)})
        }
    }

    #[tokio::test]
    async fn create_key() -> Result<(), anyhow::Error>{

        let tpm = TpmStorage::new_test_instance()?;
        let signing_key = tpm.create_signing_key(&TpmKeyType::P256);
        assert!(signing_key.is_ok(), "{}", signing_key.err().unwrap());
        Ok(())
    }

    #[tokio::test]
    async fn store_key() -> Result<(), anyhow::Error>{
        let tpm = TpmStorage::new_test_instance()?;
        let handle = tpm.get_free_handle()?;
        let (key, public) = tpm.create_signing_key(&TpmKeyType::P256)?;
        Ok(())
    }
}