use std::{collections::HashMap, sync::{Arc, Mutex, MutexGuard, RwLock}};

use identity_jose::{jwk::Jwk, jws::JwsAlgorithm};
use identity_storage::{KeyId, KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};
use tss_esapi::{abstraction::AsymmetricAlgorithmSelection, attributes::{ObjectAttributes, SessionAttributesBuilder}, constants::SessionType, handles::{AuthHandle, KeyHandle, ObjectHandle, PersistentTpmHandle, TpmHandle}, interface_types::{algorithm::{HashingAlgorithm, PublicAlgorithm}, ecc::EccCurve, reserved_handles::Hierarchy, session_handles::{AuthSession, PolicySession}}, structures::{Digest, EccParameter, EccPoint, EccScheme, EncryptedSecret, HashScheme, IdObject, Name, Public, PublicBuilder, PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinition}, traits::{Marshall, UnMarshall}, utils::PublicKey, Context};

use crate::error::{BadInput, TpmStorageError};

/// Supported key types for TPM Storage
#[derive(Debug, Clone, Copy)]
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


pub type TpmKeyId = KeyId;
pub type TpmObjectName = String;
pub type TpmObjectCache = HashMap<TpmKeyId, ObjectHandle>;

/// Storage implementation that uses the TPM for securely storing JWKs.
#[derive(Debug)]
pub struct TpmStorage{
    pub (crate) ctx: Mutex<Context>,
    pub (crate) session: Arc<Option<AuthSession>>,

    cache: RwLock<TpmObjectCache>
}


impl TpmStorage {
    /// Generating a new TpmStorage struct
    pub fn new(context: Context) -> Result<TpmStorage, TpmStorageError>{
        let mut ctx = context;
        // Generate an Auth Session for TPM communication.
        let auth_session = ctx.start_auth_session(None, None, None, 
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256)
            .map_err(|e| {TpmStorageError::StartupError(e.to_string())})?;

        Ok(TpmStorage{ctx: Mutex::new(ctx),
            session: Arc::new(auth_session),
            cache: RwLock::new(TpmObjectCache::new())})
    }

    pub (crate) fn match_kty_with_alg(key_type: &TpmKeyType, alg: &JwsAlgorithm) -> KeyStorageResult<()>{
        match (key_type, alg) {
            (TpmKeyType::P256, JwsAlgorithm::ES256) => Ok(()),
            _ => Err(KeyStorageError::new(
                KeyStorageErrorKind::KeyAlgorithmMismatch
            ).with_custom_message(format!("Cannot use keytype {key_type} with algorithm {alg}")))
        }
    }

    /// Retrieve EK certificate stored in the NV index
    pub fn ek_certificate(&self)-> Result<Vec<u8>, TpmStorageError> {
        let mut ctx =  self.get_context()?;
        let cert = tss_esapi::abstraction::ek::retrieve_ek_pubcert(&mut ctx, AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256))?;
        Ok(cert)
    }

    pub fn activate_credential(&self, ek_handle: u32, activated_key: KeyId, id_obj: &[u8], enc_sec: &[u8]) -> Result<Vec<u8>, TpmStorageError>{
        let mut ctx =  self.get_context()?;
        let cache = self.cache.try_read()
        .map_err(|_| {TpmStorageError::UnexpectedBehaviour("Cannot access cache".to_owned())})?;
        
        // load EK
        let handle = ctx.tr_from_tpm_public(TpmHandle::Persistent(PersistentTpmHandle::new(ek_handle)?))?;

        // load key to verify
        let obj_handle = cache.get(&activated_key).ok_or(TpmStorageError::KeyNotFound)?;

        // parse make credential result
        let id_obj = IdObject::from_bytes(id_obj)?;
        let enc_sec = EncryptedSecret::from_bytes(enc_sec)?;

        // authenticate session for key to activate
        let session = ctx.start_auth_session
            (None, 
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_128_CFB,
                HashingAlgorithm::Sha256)?
            .ok_or(TpmStorageError::UnexpectedBehaviour("Cannot generate a session".to_owned()))?;

        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();

        ctx.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)?;

        // session for endorsement

        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();
        let policy_auth_session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(TpmStorageError::UnexpectedBehaviour("Cannot generate a session".to_owned()))?;


        ctx.tr_sess_set_attributes(policy_auth_session, session_attributes, session_attributes_mask)?;
        ctx.execute_with_nullauth_session(|context| {
            context.policy_secret(
                PolicySession::try_from(policy_auth_session)?,
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None)
        })?;
        // solve the challenge
        let secret = ctx.execute_with_sessions((*self.session, Some(policy_auth_session), None), |context|
             context.activate_credential(obj_handle.clone().into(), handle.into(), id_obj, enc_sec))?
             .to_vec();
        
        Ok(secret)
    }

    // Create challenge for client TPM
    pub fn make_credential(&self, ek_pub: &[u8], obj_name: &[u8], secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TpmStorageError>
    {
        let mut ctx =  self.get_context()?;
        let ek_pub = Public::unmarshall(ek_pub)?;
        let obj_name = Name::try_from(Vec::from(obj_name))?;
        let credential = Digest::from_bytes(secret)?;

        let handle = ctx.load_external_public(ek_pub, Hierarchy::Null)?;
        let credential_result = ctx.make_credential(handle, credential, obj_name)?;

        Ok((credential_result.0.to_vec(), credential_result.1.to_vec()))
    }

    /// Retrieve EK public part
    pub fn read_public(&self, handle: u32) -> Result<Vec<u8>, TpmStorageError>{
        let mut ctx =  self.get_context()?;
        
        ctx.execute_with_nullauth_session(|context| {
            let handle = context.tr_from_tpm_public(TpmHandle::Persistent(PersistentTpmHandle::new(handle)?))?;
            let (public, _, _) = context.read_public(handle.into())?;
            Ok(public.marshall()?)
        })
    }

    /// Read the name of a TPM Object. 
    /// The object name must be checked in order to check that the requested key is actually the one retrived using the TPM handle
    fn get_name(context: &mut Context, object_handle: ObjectHandle) -> Result<Vec<u8>, TpmStorageError>{
        context.tr_get_name(object_handle)
            .map_err(|_|{TpmStorageError::KeyNotFound})
            .and_then(|name| {Ok(Vec::from(name.value()))})
    }
    
    /// This function aquires a lock on the function, than it releases the lock.
    fn get_context(&self) -> Result<MutexGuard<Context>, TpmStorageError>{
        self.ctx.lock()
        .map_err(|_| {TpmStorageError::DeviceUnavailableError})
    }

    fn select_ecc_key_parameters(key_type: TpmKeyType, unique: Option<&[u8]>) -> Result<Public, TpmStorageError>{

        let (crv, hashing) = match key_type {
            TpmKeyType::P256 => (EccCurve::NistP256, HashingAlgorithm::Sha256)
        };

        let ecc_parameter= match unique {
            Some(data) => EccParameter::from_bytes(data)
                .map_err(|_| {TpmStorageError::BadInput(BadInput::InputSize("keyId".to_owned()))})?,
            None => EccParameter::default(),
        };

        let unique_identifier= EccPoint::new(ecc_parameter.clone(), ecc_parameter);

        let attributes = ObjectAttributes::new_fixed_signing_key();

        let ecc_parameters = PublicEccParametersBuilder::new_unrestricted_signing_key(
            EccScheme::EcDsa(HashScheme::new(hashing)),
            crv).build()
            .map_err(|e| {TpmStorageError::KeyGenerationError(e.to_string())})?;
        PublicBuilder::new()
        .with_ecc_parameters(ecc_parameters)
        .with_ecc_unique_identifier(unique_identifier)
        .with_object_attributes(attributes)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .build()
        .map_err(|e| {TpmStorageError::KeyGenerationError(e.to_string())})
    }
    
    /// Generate the correct [`Public`] structure starting from a [`TpmKeyType`]
    fn select_key_parameters(key_type: TpmKeyType, unique: Option<&[u8]>) -> Result<Public, TpmStorageError>{
        match key_type {
            TpmKeyType::P256 => Self::select_ecc_key_parameters(key_type, unique),
        }
    }
    
    /// Create a key for signing operation protected in the TPM.
    /// ### Args
    /// - key_type: [TpmKeyType]
    /// - key_id: [KeyId] identifier required for key creation
    /// ---
    /// ### Returns
    /// The public key corresponding to the provided `key_id` 
    pub (crate) fn create_signing_key(&self, key_type: TpmKeyType, key_id: &TpmKeyId) -> Result<(PublicKey, TpmObjectName), TpmStorageError>{
        let mut ctx =  self.get_context()?;
        let mut cache = self.cache.try_write()
            .map_err(|_| {TpmStorageError::UnexpectedBehaviour("Cannot access Cache".to_owned())})?;
        
        let unique= hex::decode(key_id.as_str())
            .map_err(|_| {TpmStorageError::BadInput(BadInput::InputSize("keyId".to_owned()))})?;

        let public = Self::select_key_parameters(key_type, Some(&unique))?;
        let key_result = ctx.execute_with_session(*self.session, |ctx| -> Result<(PublicKey, TpmObjectName, KeyHandle), TpmStorageError>{
            let key = ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
                .map_err(|e|{TpmStorageError::KeyGenerationError(e.to_string())})?;

            let name= Self::get_name(ctx, key.key_handle.into())
                .and_then(|bytes| {Ok(hex::encode(bytes))})?;

            let public_key = PublicKey::try_from(key.out_public)
                .map_err(|e|{TpmStorageError::KeyGenerationError(e.to_string())})?;
        
            Ok((public_key, name, key.key_handle))
        })?;

        // add the new key to the cache
        cache.insert(key_id.clone(), key_result.2.into());
        Ok((key_result.0, key_result.1))
    }
    


    fn get_signature_scheme(alg: &str) -> Result<SignatureScheme, TpmStorageError>{
        match alg {
            "ES256" => Ok(SignatureScheme::EcDsa { scheme: HashScheme::new(HashingAlgorithm::Sha256) }),
            _ => Err(TpmStorageError::BadInput(BadInput::SignatureAlgorithm))
        }
    }

    fn get_signature_result(signature: Signature) -> Result<Vec<u8>, TpmStorageError>{
        match signature {
            Signature::EcDsa(sig ) => Ok([sig.signature_r().as_bytes(), sig.signature_s().as_bytes()].concat()),
            _ => Err(TpmStorageError::SignatureError("bad signature result".to_owned()))
        }
    }

    fn hash(message: &[u8], alg: HashingAlgorithm) -> Result<Digest, TpmStorageError>{
        let digest = match alg {
            HashingAlgorithm::Sha256 => {
                // Hash the message with the required algorithm
                let mut digest = [0u8; crypto::hashes::sha::SHA256_LEN];
                crypto::hashes::sha::SHA256(message, &mut digest);
                digest
            }
            _ => return Err(TpmStorageError::Unsupported(format!("{:?}", alg)))
        };

        let hash = Digest::from_bytes(digest.as_slice())
            .map_err(|e| {TpmStorageError::UnexpectedBehaviour(e.to_string())})?;

        Ok(hash)
    }

    /// Generate a Signature using keys owned by the TPM
    /// 
    /// ---
    /// #### Params
    /// - **key_id**: key identifier of the key for signature
    /// - **data**: payload to be signed
    /// - **jwk**: public Jwk containing the name in the kid property. It is checked to guarantee that the signature is performed with the correct key.
    /// ---
    /// #### Returns
    /// - Signature bytes as a [Vec<u8>]
    pub (crate) fn tpm_sign(&self, key_id: &TpmKeyId, data: &[u8],jwk: &Jwk) -> Result<Vec<u8>, TpmStorageError>{
        // Check input data
        let alg = jwk.alg().ok_or(TpmStorageError::BadInput(BadInput::SignatureAlgorithm))?;
        let jwk_kid = jwk.kid().ok_or(TpmStorageError::BadInput(BadInput::InputSize("keyId".to_owned())))?;
        let scheme = Self::get_signature_scheme(alg)
            .map_err(|_| {TpmStorageError::BadInput(BadInput::SignatureAlgorithm)})?;

        // Read the key from cache
        let handle = self.cache.try_read()
            .map_err(|_| {TpmStorageError::UnexpectedBehaviour("Cannot access cache".to_owned())})
            .and_then(|cache| {cache.get(key_id).ok_or(TpmStorageError::KeyNotFound).copied()})?;

        // Read the name of the key and check it with the Jwk
        let mut ctx = self.get_context()?;

        let name = Self::get_name(&mut ctx, handle.clone())
            .and_then(|bytes| {Ok(hex::encode(bytes))})?;

        // Guard the rest of the function if the name is not correct
        if name.ne(jwk_kid) {
            return Err(TpmStorageError::BadInput(BadInput::Jwk))
        }

        // Hash the message with the required algorithm
        let hash = Self::hash(data, scheme.signing_scheme()?)?;
        
        // Sign
        let signature = ctx.execute_with_session(*self.session, |context| {
            context.sign(handle.into(), hash, scheme, None)
            .map_err(|e| {TpmStorageError::SignatureError(e.to_string())})
        })?;

        Self::get_signature_result(signature)
    }

    /// Delete a key from cache
    /// If the key is not found a KeyNotFound error is return
    pub (crate) fn delete_key(&self, key_id: &TpmKeyId)-> Result<(), TpmStorageError>{
        self.cache.try_write()
            .map_err(|_| {TpmStorageError::UnexpectedBehaviour("Cannot access cache".to_owned())})?
            .remove(&key_id)
            .ok_or(TpmStorageError::KeyNotFound)?;
        Ok(())
    }
    
    /// Generate random `size` bytes using the TPM TRNG
    fn random(&self, ctx: &mut Context ,size: usize) -> Result<Vec<u8>, TpmStorageError>{
        ctx.get_random(size)
            .map_err(|_| {TpmStorageError::BadInput(BadInput::InputSize("random size".to_owned()))})
            .and_then(|digest| {Ok(Vec::from(digest.as_bytes()))})
    }

    /// Generate a random KeyId for TpmStorage
    /// ### Returns
    /// Random [TpmKeyId] of fixed size of 32 bytes.
    pub (crate) fn new_key_id(&self) -> Result<TpmKeyId, TpmStorageError>{
        let mut ctx = self.get_context()?;
        let bytes= self.random(&mut ctx, 32)?;
        let hex = hex::encode(bytes);
        Ok(TpmKeyId::new(hex))
    }

    pub(crate) fn contains(&self, key_id: &TpmKeyId) -> Result<bool, TpmStorageError>{
        self.cache.try_read()
            .map_err(|_| {TpmStorageError::UnexpectedBehaviour("Cannot access cache".to_owned())})
            .and_then(|cache| {Ok(cache.contains_key(key_id))})
    }

}


#[cfg(test)]
pub (crate) mod tests {

    use identity_storage::JwkStorage;
    use tss_esapi::constants::StartupType;

    use super::*;

    impl TpmStorage {
        pub(crate) fn new_test_instance() -> Result<TpmStorage, TpmStorageError> {
            let location = tss_esapi::Tcti::Tabrmd(tss_esapi::tcti_ldr::TabrmdConfig::default());
            let mut ctx = Context::new(location)
                .map_err(|_| {TpmStorageError::StartupError("Test instance cannot reache the simulator".to_owned())})?;

            // TPM Simulator startup
            let _ = ctx.startup(StartupType::Clear)
                .map_err(|_| {TpmStorageError::StartupError("Cannot communicate with the simulator".to_owned())})?;
            Self::new(ctx)
        }

    }

    #[tokio::test]
    async fn create_key() -> Result<(), anyhow::Error>{
        let tpm = TpmStorage::new_test_instance()?;
        //1. Generate a Key
        let kid = tpm.new_key_id()?;
        let signing_key = tpm.create_signing_key(TpmKeyType::P256, &kid);
        assert!(signing_key.is_ok(), "{}", signing_key.err().unwrap());
        
        //1.1 ensure it is cached
        let obj_ref;
        {
            let cache = tpm.cache.try_read().unwrap();
            assert_eq!(cache.len(), 1);
            assert!(cache.contains_key(&kid));
            obj_ref = cache.get(&kid).copied();
        }

        //2. Create the same key twice, ensure it's equal
        let other_kid = KeyId::from(kid.clone());
        let other_key = tpm.create_signing_key(TpmKeyType::P256, &other_kid);
        assert!(other_key.is_ok(), "{}", other_key.err().unwrap());
        let signing_key = signing_key.unwrap();
        assert_eq!(signing_key, other_key.unwrap());

        //2.1 Ensure the new object is cached
        {
            let cache = tpm.cache.try_read().unwrap();
            assert_eq!(&kid.as_str(), &other_kid.as_str());
            assert_eq!(cache.len(), 1);
            assert!(cache.contains_key(&other_kid));
            assert_ne!(obj_ref, cache.get(&other_kid).copied());
        }
        
        //3. Generate a different key
        let other_kid = tpm.new_key_id()?;
        let other_key = tpm.create_signing_key(TpmKeyType::P256, &other_kid);
        assert!(other_key.is_ok(), "{}", other_key.err().unwrap());
        assert_ne!(signing_key, other_key.unwrap());

        //3.1 Ensure the new object is cached
        {
            let cache = tpm.cache.try_read().unwrap();
            assert_ne!(&kid.as_str(), &other_kid.as_str());
            assert_eq!(cache.len(), 2);
            assert!(cache.contains_key(&other_kid));
            assert_ne!(obj_ref, cache.get(&other_kid).copied());
        }

        Ok(())
    }

    #[tokio::test]
    async fn store_and_delete_key() -> Result<(), anyhow::Error>{
        let tpm = TpmStorage::new_test_instance()?;
        // key generation
        let kid = tpm.new_key_id()?;
        let (_, _) = tpm.create_signing_key(TpmKeyType::P256, &kid)?;

        // delete once
        let result = tpm.delete_key(&kid);
        assert!(result.is_ok());

        // delete twice 
        let result = tpm.delete_key(&kid);
        assert!(result.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn sign_message() -> Result<(), anyhow::Error>{
        let tpm = TpmStorage::new_test_instance()?;
        let result = tpm.generate(KeyType::from("P-256"), JwsAlgorithm::ES256).await?;
        let kid = result.key_id;
        let signature = tpm.tpm_sign(&kid, "tpm signature test".as_bytes(), &result.jwk);
        assert!(signature.is_ok(), "{}", signature.err().unwrap());
        Ok(())
    }
}