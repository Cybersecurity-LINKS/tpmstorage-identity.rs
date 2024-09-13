use std::sync::{Arc, Mutex};

use identity_jose::jws::JwsAlgorithm;
use identity_storage::{KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType};
use tss_esapi::{Context, Tcti};

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

impl TpmStorage {
    pub fn new(location: Tcti) -> Result<TpmStorage, tss_esapi::Error>{
        let ctx = Context::new(location)?;
        return Ok(TpmStorage{ctx: Arc::new(Mutex::new(ctx))})
    }
    
    fn match_kty_with_alg(key_type: &TpmKeyType, alg: &JwsAlgorithm) -> KeyStorageResult<()>{
        match (key_type, alg) {
            (TpmKeyType::P256, JwsAlgorithm::ES256) => Ok(()),
            _ => Err(KeyStorageError::new(
                KeyStorageErrorKind::KeyAlgorithmMismatch
            ).with_custom_message(format!("Cannot use keytype {key_type} with algorithm {alg}")))
        }
    }
}