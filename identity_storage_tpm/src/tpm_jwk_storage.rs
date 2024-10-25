use async_trait::async_trait;
use identity_jose::{jwk::Jwk, jws::JwsAlgorithm};
use identity_storage::{JwkGenOutput, JwkStorage, KeyId, KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};

use crate::tpm_storage::{TpmKeyType, TpmStorage};

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
        let kid: KeyId = self.new_key_id()
            .map_err(|_| {KeyStorageError::new(KeyStorageErrorKind::Unavailable).with_custom_message("Cannot create a random KeyId")})?;

        // Generate a new key
        let (public, name) = self.create_signing_key(key_type.into(), &kid)
            .map_err(|_| {KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message("Cannot create the key")})?;
        
        // Create Jwk
        let mut jwk = TpmStorage::encode_jwk(key_type, public)?;
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
        self.tpm_sign(key_id, data, public_key)
            .map_err(|_| {KeyStorageError::new(KeyStorageErrorKind::Unspecified)})
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
        self.delete_key(key_id)
            .map_err(|_| {KeyStorageError::new(KeyStorageErrorKind::KeyNotFound)})
    }

    /// Returns `true` if the key with the given `key_id` exists in storage, `false` otherwise.
    async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool>{
        todo!("Fix");
    }
}

#[cfg(test)]
mod tests{

    use identity_jose::jws::JwsAlgorithm;
    use identity_storage::{JwkStorage, KeyStorageError, KeyStorageErrorKind, KeyType};

    use crate::tpm_storage::TpmStorage;

    #[tokio::test]
    async fn generate() -> Result<(), anyhow::Error>{
        let tpm = TpmStorage::new_test_instance()?;
        let result = tpm.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await;
        assert!(result.is_ok(), "{}", result.unwrap_err().to_string());
        let result = result.unwrap();
        println!("{:#?}", result);
        Ok(())
    }

    #[tokio::test]
    async fn generate_incompatible_algs(){
        let tpm = TpmStorage::new_test_instance().unwrap();
        let result = tpm.generate(KeyType::new("P-256"), JwsAlgorithm::RS512).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn generate_unsupported_key(){
        let tpm = TpmStorage::new_test_instance().unwrap();
        let result = tpm.generate(KeyType::new("EdDSA"), JwsAlgorithm::ES256).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn delete(){
        let tpm = TpmStorage::new_test_instance().unwrap();
        let output = tpm.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await.unwrap();

        // delete once
        let result = tpm.delete(&output.key_id).await;
        assert!(result.is_ok());

        //delete twice
        let result = tpm.delete(&output.key_id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn sign(){
        let tpm = TpmStorage::new_test_instance().unwrap();
        let result = tpm.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await.unwrap();
        let signature = tpm.sign(&result.key_id, "some message to sign".as_bytes(), &result.jwk).await;
        assert!(signature.is_ok(), "{}", signature.err().unwrap());
    }
}