use std::{ops::Deref, sync::{Arc, Mutex, MutexGuard}};

use identity_jose::{jwk::{Jwk, JwkParamsEc}, jws::JwsAlgorithm, jwu::{self}};
use identity_storage::{KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};
use tss_esapi::{attributes::ObjectAttributes, constants::SessionType, handles::{ObjectHandle, PersistentTpmHandle, TpmHandle}, interface_types::{algorithm::{HashingAlgorithm, PublicAlgorithm}, dynamic_handles::Persistent, ecc::EccCurve, resource_handles::{Hierarchy, Provision}, session_handles::AuthSession}, structures::{CapabilityData, EccPoint, EccScheme, HashScheme, MaxBuffer, Public, PublicBuilder, PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinition}, utils::PublicKey, Context};
use anyhow::{anyhow, Result};

use crate::{error::TpmStorageError, tpm_key_id::TpmKeyId};

/// Supported key types for TPM Storage
#[derive(Debug)]
pub enum TpmKeyType{
    P256,
}

pub type TpmObjectName = String;

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
#[derive(Debug)]
pub struct TpmStorage{
    pub (crate) ctx: Arc<Mutex<Context>>,
    pub (crate) session: Arc<Option<AuthSession>>
}

const HANDLE_STORAGE_FIRST_INDEX:u32 = 0x81008000;
const HANDLE_STORAGE_LAST_INDEX:u32 = 0x8100FFFF;

impl TpmStorage {
    /// Generating a new TpmStorage struct
    pub fn new(context: Context) -> Result<TpmStorage>{
        let mut ctx = context;
        // Generate an Auth Session for TPM communication.
        let auth_session = ctx.start_auth_session(None, None, None, 
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256)?;

        Ok(TpmStorage{ctx: Arc::new(Mutex::new(ctx)), session: Arc::new(auth_session)})
    }

    pub (crate) fn match_kty_with_alg(key_type: &TpmKeyType, alg: &JwsAlgorithm) -> KeyStorageResult<()>{
        match (key_type, alg) {
            (TpmKeyType::P256, JwsAlgorithm::ES256) => Ok(()),
            _ => Err(KeyStorageError::new(
                KeyStorageErrorKind::KeyAlgorithmMismatch
            ).with_custom_message(format!("Cannot use keytype {key_type} with algorithm {alg}")))
        }
    }

    /// Read the name of a TPM Object. 
    /// The object name must be checked in order to check that the requested key is actually the one retrived using the TPM handle
    fn get_name(context: &mut Context, object_handle: ObjectHandle) -> Result<Vec<u8>, TpmStorageError>{
        context.tr_get_name(object_handle)
            .map_err(|_|{TpmStorageError::BadAddressError("key not found".to_owned())})
            .and_then(|name| {Ok(Vec::from(name.value()))})
    }
    
    /// List the persistent handles currently used
    fn used_handles(ctx: &mut Context)-> Result<Vec<u32>>{
        //init loop for reading handles
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

        Ok(handles)
    }

    // This function aquires a lock on the function, than it releases the lock.
    fn get_context(&self) -> Result<MutexGuard<Context>, TpmStorageError>{
        self.ctx.lock()
        .map_err(|_| {TpmStorageError::DeviceUnavailableError})
    }

    /// This function returns an handle address that can be used for persistent storage in the Owner Hierarchy.
    /// The return value is the first empty handler starting from `HANDLE_STORAGE_FIRST_INDEX`
    pub (crate) fn get_free_handle(&self) -> Result<TpmKeyId>{
        let mut ctx = self.get_context()?;
        
        let used_handles = Self::used_handles(&mut ctx)?;

        // Finding the first handle not in the list, starting from the first index.
        let free_handle:u32 = match (HANDLE_STORAGE_FIRST_INDEX..=HANDLE_STORAGE_LAST_INDEX)
        .find(|address| {!used_handles.contains(address)}){
            Some(handle) => handle,
            None => return Err(anyhow!("The persistent storage is full!"))
        };

        Ok(TpmKeyId::from(free_handle))
    }

    pub (crate) fn contains(&self, key_id: &TpmKeyId) -> Result<bool, TpmStorageError>{
        let mut ctx = self.get_context()?;

        let used_handles = Self::used_handles(&mut ctx)
            .map_err(|_|{TpmStorageError::UnexpectedBehaviour("cannot read used handles".to_owned())})?;

        Ok(used_handles.contains(&key_id))
    }

    fn select_ecc_key_parameters(key_type: &TpmKeyType) -> Result<Public, TpmStorageError>{

        let (crv, hashing) = match key_type {
            TpmKeyType::P256 => (EccCurve::NistP256, HashingAlgorithm::Sha256)
        };

        let attributes = ObjectAttributes::new_fixed_signing_key();

        let ecc_parameters = PublicEccParametersBuilder::new_unrestricted_signing_key(
            EccScheme::EcDsa(HashScheme::new(hashing)),
            crv).build()
            .map_err(|e| {TpmStorageError::KeyGenerationError(e.to_string())})?;
        PublicBuilder::new()
        .with_ecc_parameters(ecc_parameters)
        .with_ecc_unique_identifier(EccPoint::default())
        .with_object_attributes(attributes)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .build()
        .map_err(|e| {TpmStorageError::KeyGenerationError(e.to_string())})
    }
    
    /// Generate the correct [`Public`] structure starting from a [`TpmKeyType`]
    fn select_key_parameters(key_type: &TpmKeyType) -> Result<Public, TpmStorageError>{
        match key_type {
            TpmKeyType::P256 => Self::select_ecc_key_parameters(key_type),
        }
    }
    
    /// Create a key for signing operation protected in the TPM.
    pub (crate) fn create_signing_key(&self, key_type: &TpmKeyType) -> Result<(PublicKey, TpmObjectName), TpmStorageError>{
        let mut ctx = self.get_context()?;

        let public = Self::select_key_parameters(key_type)?;
        ctx.execute_with_session(*self.session, |ctx| -> Result<(PublicKey, TpmObjectName)>{
            let key = ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)?;
            let name = Self::get_name(ctx, key.key_handle.into())?
            .iter().map(|byte| {format!("{:X}", byte)}).collect();

            let public_key = PublicKey::try_from(key.out_public)?;
            Ok((public_key, name))
        })
        .map_err(|e|{TpmStorageError::KeyGenerationError(e.to_string())})
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

    fn get_signature_scheme(alg: &str) -> Result<SignatureScheme>{
        match alg {
            "ES256" => Ok(SignatureScheme::EcDsa { hash_scheme: HashScheme::new(HashingAlgorithm::Sha256) }),
            _ => Err(KeyStorageError::new(KeyStorageErrorKind::KeyAlgorithmMismatch).into())
        }
    }

    fn get_signature_result(signature: Signature) -> Result<Vec<u8>, TpmStorageError>{
        match signature {
            Signature::EcDsa(sig ) => Ok([sig.signature_r().value(), sig.signature_s().value()].concat()),
            _ => Err(TpmStorageError::SignatureError("bad signature result".to_owned()))
        }
    }

    /// Load an object stored inside the persistent memory of the TPM
    fn get_tr_from_handle(context: &mut Context, handle: &TpmKeyId) -> Result<ObjectHandle, TpmStorageError>{
        let persistent_handle = PersistentTpmHandle::new(*handle.deref())
        .map_err(|e|{TpmStorageError::BadAddressError(e.to_string())})?;
        // load the resource from the TPM memory
        context.tr_from_tpm_public(TpmHandle::Persistent(persistent_handle))
            .map_err(|_| {TpmStorageError::BadInput(format!("No resource found for address {}", handle))})
    }

    pub (crate) fn tpm_sign(&self, key_id: &TpmKeyId, data: &[u8],jwk: &Jwk) -> Result<Vec<u8>, TpmStorageError>{
        let alg = jwk.alg().ok_or(TpmStorageError::BadInput(format!("jwk alg is None")))?;
        let scheme = Self::get_signature_scheme(alg)
            .map_err(|e| {TpmStorageError::BadInput(e.to_string())})?;
        let hashing_alg = scheme.signing_scheme()
            .map_err(|e| {TpmStorageError::UnexpectedBehaviour(e.to_string())})?; // should not happen since this struct is setting the proper scheme
        let data = MaxBuffer::try_from(data)
            .map_err(|_| {TpmStorageError::BadInput("bad size of input data".to_owned())})?;

        let mut ctx = self.get_context()?;
        let (hash, ticket) = ctx.hash(data, hashing_alg, Hierarchy::Owner)
        .map_err(|_| {TpmStorageError::UnexpectedBehaviour("unsupported hashing algorithm".to_owned())})?;
        let obj_handle = Self::get_tr_from_handle(&mut ctx, key_id)?;
        let signature = ctx.execute_with_session(*self.session, |context| {
            context.sign(obj_handle.into(), hash, scheme, ticket)
            .map_err(|e| {TpmStorageError::SignatureError(e.to_string())})
        })?;

        Self::get_signature_result(signature)
    }

    pub (crate) fn delete_key(&self, key_id: &TpmKeyId)-> Result<(), TpmStorageError>{
        let mut ctx = self.get_context()?;

        let persistent = PersistentTpmHandle::new(key_id.value())
            .map_err(|e|{TpmStorageError::BadAddressError(e.to_string())})?;
        let obj_handle = Self::get_tr_from_handle(&mut ctx, key_id)?;

        ctx.execute_with_session(*self.session, |context| {
            context.evict_control(Provision::Owner, obj_handle, Persistent::Persistent(persistent))
                .map_err(|e|{TpmStorageError::DeleteError { handle: key_id.clone(), reason: e.to_string() }})?;
            Ok(())
        })
    }

}


#[cfg(test)]
pub (crate) mod tests {
    use identity_storage::JwkStorage;
    use tss_esapi::{constants::StartupType, tcti_ldr::NetworkTPMConfig};

    use super::*;

    impl TpmStorage {
        pub(crate) fn new_test_instance() -> Result<TpmStorage> {
            let location = tss_esapi::Tcti::Mssim(NetworkTPMConfig::default());
            let mut ctx = Context::new(location)?;
            // TPM Simulator startup
            let _ = ctx.startup(StartupType::Clear)?;
            Self::new(ctx)
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
    async fn store_and_delete_key() -> Result<(), anyhow::Error>{
        let tpm = TpmStorage::new_test_instance()?;
        // key generation
        let handle = tpm.get_free_handle()?;
        let (_, _) = tpm.create_signing_key(&TpmKeyType::P256)?;

        // key storage
        //let handle = tpm.store_key(key, handle);
        //assert!(handle.is_ok(), "{}", handle.err().unwrap());
        //let handle = handle.unwrap();
        // key deletion
        //let delete_result = tpm.delete_key(&handle);
        //assert!(delete_result.is_ok(), "{}", delete_result.err().unwrap());

        Ok(())
    }

    #[tokio::test]
    async fn sign_message() -> Result<(), anyhow::Error>{
        let tpm = TpmStorage::new_test_instance()?;
        let result = tpm.generate(KeyType::from("P-256"), JwsAlgorithm::ES256).await?;
        let kid = TpmKeyId::try_from(result.key_id.as_str())?;
        let signature = tpm.tpm_sign(&kid, "tpm signature test".as_bytes(), &result.jwk);
        assert!(signature.is_ok(), "{}", signature.err().unwrap());
        println!("Signature {:?}", signature.unwrap());
        Ok(())
    }
}