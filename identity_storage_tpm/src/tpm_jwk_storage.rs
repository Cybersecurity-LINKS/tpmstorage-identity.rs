use async_trait::async_trait;
use identity_jose::{jwk::Jwk, jws::JwsAlgorithm};
use identity_storage::{JwkGenOutput, JwkStorage, KeyId, KeyStorageResult, KeyType};

use crate::tpm_storage::TpmStorage;

#[async_trait(?Send)]
impl JwkStorage for TpmStorage{
    /// Generate a new key represented as a JSON Web Key.
    ///
    /// It is recommended that the implementer exposes constants for the supported [`KeyType`].
    async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput>{
        todo!()
    }
    /// Insert an existing JSON Web Key into the storage.
    ///
    /// All private key components of the `jwk` must be set.
    async fn insert(&self, jwk: Jwk) -> KeyStorageResult<KeyId>{
        todo!()
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