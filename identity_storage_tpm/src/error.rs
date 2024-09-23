use core::error;


#[derive(Debug, thiserror::Error)]
pub enum TpmStorageError{
    #[error("Cannot access the TPM Device")]
    DeviceUnavailableError,
    #[error("InvalidAddress: {0}")]
    BadAddressError(String)
}