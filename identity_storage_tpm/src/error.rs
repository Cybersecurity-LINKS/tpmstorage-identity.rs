
#[derive(Debug, thiserror::Error)]
pub enum TpmStorageError{
    #[error("Cannot access the TPM Device")]
    DeviceUnavailableError
}