use async_trait::async_trait;
use identity_jose::{jwk::Jwk, jws::JwsAlgorithm};
use identity_storage::{JwkGenOutput, JwkStorage, KeyId, KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;

use crate::tpm_storage::{TpmKeyType, TpmStorage};

#[async_trait(?Send)]
impl JwkStorage for TpmStorage{
    /// Generate a new key represented as a JSON Web Key.
    ///
    /// It is recommended that the implementer exposes constants for the supported [`KeyType`].
    async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput>{
        
        // parameters check
        let key_type = TpmKeyType::try_from(&key_type)?;
        TpmStorage::match_kty_with_alg(&key_type, &alg)?;

        // Assign a new KeyId
        let handle = self.get_free_handle()
        .map_err(|e| {KeyStorageError::new(KeyStorageErrorKind::Unavailable)
            .with_custom_message(e.to_string())})?;
        
        let kid: KeyId = KeyId::from(handle.clone());

        // Generate a new key
        let (key_obj, public) = self.create_signing_key(&key_type)
        .map_err(|err| {KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message("Cannot create the key")})?;

        // Store the Key
        self.store_key(key_obj, handle)
        .map_err(|e|{KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(e.to_string())})?;

        // Create Jwk
        let mut jwk = TpmStorage::encode_jwk(&key_type, public)?;
        jwk.set_alg(alg.name());
        jwk.set_kid(jwk.thumbprint_sha256_b64());
        let public_jwk = jwk.to_public().expect("unexpected error during jwk generation");

        Ok(JwkGenOutput::new(kid, public_jwk))
    }

    /// Insert an existing JSON Web Key into the storage.
    ///
    /// All private key components of the `jwk` must be set.
    /// ### Warning
    /// If called an Error is always returned.
    /// This method cannot be used inside the TPM. 
    /// Importing an external key inside the TPM is not supported.
    async fn insert(&self, jwk: Jwk) -> KeyStorageResult<KeyId>{
        Err(KeyStorageError::new(KeyStorageErrorKind::Unavailable)
        .with_custom_message("Cannot store external keys inside the TPM device"))
    }

    /// Sign the provided `data` using the private key identified by `key_id` according to the requirements of
    /// the corresponding `public_key` (see [`Jwk::alg`](Jwk::alg()) etc.).
    ///
    /// # Note
    ///
    /// High level methods from this library calling this method are designed to always pass a `public_key` that
    /// corresponds to `key_id` and additional checks for this in the `sign` implementation are normally not required.
    /// This is however based on the expectation that the key material associated with a given [`KeyId`] is immutable.  
    async fn sign(&self, key_id: &KeyId, data: &[u8], public_key: &Jwk) -> KeyStorageResult<Vec<u8>>{
        todo!()
    }

    /// Deletes the key identified by `key_id`.
    ///
    /// If the corresponding key does not exist in storage, a [`KeyStorageError`] with kind
    /// [`KeyNotFound`](crate::key_storage::KeyStorageErrorKind::KeyNotFound) must be returned.
    ///
    /// # Warning
    ///
    /// This operation cannot be undone. The keys are purged permanently.
    async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()>{
        todo!()
    }

    /// Returns `true` if the key with the given `key_id` exists in storage, `false` otherwise.
    async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool>{
        todo!()
    }
}