use identity_storage::JwkStorage;
use tss_esapi::{tcti_ldr::DeviceConfig, Context, Tcti};

/// Storage implementation that uses the TPM for securely storing JWKs.
pub struct TpmStorage{
    ctx: Context
}

impl TpmStorage {
    pub fn new(location: Tcti) -> Result<TpmStorage, tss_esapi::Error>{
        let ctx = Context::new(location)?;
        return Ok(TpmStorage{ctx})
    }
    
}