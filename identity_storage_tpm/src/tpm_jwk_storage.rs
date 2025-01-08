use async_trait::async_trait;
use identity_jose::{jwk::Jwk, jws::JwsAlgorithm};
use identity_storage::{JwkGenOutput, JwkStorage, KeyId, KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};

use crate::{error::{BadInput, TpmStorageError}, tpm_storage::{TpmKeyType, TpmStorage}};

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
            .map_err(|e| {TpmStorage::convert_error(e)})?;

        // Generate a new key
        let (public, name) = self.create_signing_key(key_type.into(), &kid)
            .map_err(|e| {TpmStorage::convert_error(e)})?;

        
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
            .map_err(|e| {TpmStorage::convert_error(e)})

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
            .map_err(|e| {TpmStorage::convert_error(e)})
    }

    /// Returns `true` if the key with the given `key_id` exists in storage, `false` otherwise.
    async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool>{
        self.contains(key_id)
            .map_err(|e| {TpmStorage::convert_error(e)})
    }
}

impl TpmStorage{
    pub (crate) fn convert_error(error: TpmStorageError) -> KeyStorageError {
        let (kind, message) = match error {
            TpmStorageError::DeviceUnavailableError => (KeyStorageErrorKind::Unavailable, None),
            TpmStorageError::StartupError(_) => (KeyStorageErrorKind::Unspecified, None),
            TpmStorageError::KeyGenerationError(mes) => (KeyStorageErrorKind::RetryableIOFailure, Some(mes)),
            TpmStorageError::KeyNotFound => (KeyStorageErrorKind::KeyNotFound, None),
            TpmStorageError::BadInput(BadInput::KeyType) => (KeyStorageErrorKind::UnsupportedKeyType, None),
            TpmStorageError::BadInput(BadInput::InputSize(mes)) => (KeyStorageErrorKind::Unspecified, Some(mes)),
            TpmStorageError::BadInput(BadInput::Jwk) => (KeyStorageErrorKind::Unspecified, Some(TpmStorageError::BadInput(BadInput::Jwk).to_string())),
            TpmStorageError::BadInput(BadInput::SignatureAlgorithm) => (KeyStorageErrorKind::UnsupportedSignatureAlgorithm, None),
            TpmStorageError::UnexpectedBehaviour(mes) => (KeyStorageErrorKind::Unspecified, Some(mes)),
            TpmStorageError::SignatureError(mes) => (KeyStorageErrorKind::RetryableIOFailure, Some(mes)),
            TpmStorageError::Unsupported(mes) => (KeyStorageErrorKind::Unspecified, Some(mes)),
            TpmStorageError::TSSError(error) => (KeyStorageErrorKind::Unspecified, Some(error.to_string())),
        };

        let mut error = KeyStorageError::new(kind);

        if let Some(custom_message) = message{
            error = error.with_custom_message(custom_message);
        }

        error
    }
}

impl TpmStorage {
    fn encode_ec_jwk(key_type: TpmKeyType, x: impl AsRef<[u8]>, y: impl AsRef<[u8]>) -> Jwk{
        let mut params = identity_jose::jwk::JwkParamsEc::new();
        params.x = identity_jose::jwu::encode_b64(x);
        params.y = identity_jose::jwu::encode_b64(y);
        params.crv = key_type.to_string();
        Jwk::from_params(params)
    }
    
    fn encode_jwk(key_type: TpmKeyType, public_key: tss_esapi::utils::PublicKey) -> Result<Jwk, KeyStorageError>{
        match (key_type, public_key){
            (TpmKeyType::P256, tss_esapi::utils::PublicKey::Ecc { x, y }) => Ok(Self::encode_ec_jwk(key_type, &x, &y)),
            _ => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType))
        }
    }
}
#[cfg(test)]
mod tests{

    use std::sync::LazyLock;

    use identity_jose::jws::JwsAlgorithm;
    use identity_storage::{JwkStorage, KeyStorageErrorKind, KeyType};

    use crate::{error::{BadInput, TpmStorageError}, tpm_storage::TpmStorage};

    static TPM: LazyLock<TpmStorage> = LazyLock::new(|| {TpmStorage::new_test_instance().unwrap()});

    #[tokio::test]
    async fn generate() -> Result<(), anyhow::Error>{
        let result = TPM.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await;
        assert!(result.is_ok(), "{}", result.unwrap_err().to_string());
        let result = result.unwrap();
        println!("{:#?}", result);
        Ok(())
    }

    #[tokio::test]
    async fn generate_incompatible_algs(){
        let result = TPM.generate(KeyType::new("P-256"), JwsAlgorithm::RS512).await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind().as_str(), KeyStorageErrorKind::KeyAlgorithmMismatch.as_str())
        
    }

    #[tokio::test]
    async fn generate_unsupported_key(){
        let result = TPM.generate(KeyType::new("EdDSA"), JwsAlgorithm::ES256).await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind().as_str(), KeyStorageErrorKind::UnsupportedKeyType.as_str())

    }

    #[tokio::test]
    async fn delete(){
        let output = TPM.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await.unwrap();

        // delete once
        let result = TPM.delete(&output.key_id).await;
        assert!(result.is_ok());

        //delete twice
        let result = TPM.delete(&output.key_id).await;
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().kind().as_str(), KeyStorageErrorKind::KeyNotFound.as_str())
        
    }

    #[tokio::test]
    async fn sign(){
        let result = TPM.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await.unwrap();
        let signature = TPM.sign(&result.key_id, "some message to sign".as_bytes(), &result.jwk).await;
        assert!(signature.is_ok(), "{}", signature.err().unwrap());
    }

    #[tokio::test]
    async fn sign_bad_name(){
        let mut result = TPM.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await.unwrap();
        let fake_name = TPM.new_key_id().unwrap();

        result.jwk.set_kid(fake_name.as_str());

        let signature = TPM.sign(&result.key_id, b"test signature", &result.jwk).await;
        assert!(signature.is_err());
        let signature_err = signature.err().unwrap();
        assert_eq!(signature_err.kind().as_str(), KeyStorageErrorKind::Unspecified.as_str());
        assert_eq!(signature_err.custom_message().unwrap(), TpmStorageError::BadInput(BadInput::Jwk).to_string())
        
    }

    #[tokio::test]
    async fn exists(){
        let result = TPM.generate(KeyType::new("P-256"), JwsAlgorithm::ES256).await.unwrap();

        let exists = TPM.exists(&result.key_id).await;
        assert!(exists.is_ok_and(|res| {res == true}));

        TPM.delete(&result.key_id).await.unwrap();

        let exists = TPM.exists(&result.key_id).await;
        assert!(exists.is_ok_and(|res| {res == false}));
    }
}