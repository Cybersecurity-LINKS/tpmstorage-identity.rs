use async_trait::async_trait;
use identity_jose::{jwk::Jwk, jws::JwsAlgorithm};
use identity_storage::{JwkGenOutput, JwkStorage, KeyId, KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};

use crate::tpm_storage::{TpmKeyType, TpmStorage};
use crate::tpm_key_id::TpmKeyId;

#[async_trait(?Send)]
impl JwkStorage for TpmStorage{
    /// Generate a new key represented as a JSON Web Key.
    ///
    /// It is recommended that the implementer exposes constants for the supported [`KeyType`].
    async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput>{
        
        // Parameters check
        let key_type = TpmKeyType::try_from(&key_type)?;
        TpmStorage::match_kty_with_alg(&key_type, &alg)?;

        // Assign a new KeyId
        let handle = self.get_free_handle()
        .map_err(|e| {KeyStorageError::new(KeyStorageErrorKind::Unavailable)
            .with_custom_message(e.to_string())})?;

        // Generate a new key
        let (key_obj, public, name) = self.create_signing_key(&key_type)
        .map_err(|_| {KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message("Cannot create the key")})?;

        // Store the Key
        let stored_ref = self.store_key(key_obj, handle)
        .map_err(|e|{KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(e.to_string())})?;
        
        let kid: KeyId = KeyId::from(stored_ref);
        
        // Create Jwk
        let mut jwk = TpmStorage::encode_jwk(&key_type, public)?;
        jwk.set_alg(alg.name());
        jwk.set_kid(name);
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
    async fn insert(&self, _jwk: Jwk) -> KeyStorageResult<KeyId>{
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
        let kid = TpmKeyId::try_from(key_id.as_str())
            .map_err(|e| {KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(e.to_string())})?;
        self.tpm_sign(&kid, data, public_key)
        .map_err(|e| {KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(e.to_string())})
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
        let key_id = TpmKeyId::try_from(key_id.as_str())
            .map_err(|e| {KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(e.to_string())})?;

        self.delete_key(&key_id)
            .map_err(|_| {KeyStorageError::new(KeyStorageErrorKind::KeyNotFound)})
    }

    /// Returns `true` if the key with the given `key_id` exists in storage, `false` otherwise.
    async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool>{
        let key_id = TpmKeyId::try_from(key_id.as_str())
            .map_err(|e| {KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message(e.to_string())})?;

        self.contains(&key_id)
            .map_err(|e| {KeyStorageError::new(KeyStorageErrorKind::KeyNotFound).with_custom_message(e.to_string())})
    }
}

#[cfg(test)]
mod tests{
    use identity_jose::jws::JwsAlgorithm;
    use identity_storage::{JwkStorage, KeyType};

    use crate::tpm_storage::TpmStorage;
    use crate::tpm_key_id::TpmKeyId;

    #[tokio::test]
    async fn generate_and_delete_key() -> Result<(), anyhow::Error>{
        let tpm = TpmStorage::new_test_instance()?;
        let result = tpm.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await;
        assert!(result.is_ok(), "{}", result.unwrap_err().to_string());
        let result = result.unwrap();
        println!("{:#?}", result);
        let kid = TpmKeyId::try_from(result.key_id.as_str())?;

        // if generated it must exists
        assert!(tpm.contains(&kid)?);

        // delete the key
        let delete_result = tpm.delete_key(&kid);
        assert!(delete_result.is_ok(), "{}", delete_result.unwrap_err().to_string());
        println!("Deleted!");
        Ok(())
    }

    #[tokio::test]
    async fn sign() -> Result<(), anyhow::Error>{
        let tpm = TpmStorage::new_test_instance()?;
        let result = tpm.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await?;
        let signature = tpm.sign(&result.key_id, "some message to sign".as_bytes(), &result.jwk).await;
        assert!(signature.is_ok(), "{}", signature.err().unwrap());
        Ok(())
    }
}