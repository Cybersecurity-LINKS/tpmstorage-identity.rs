#[derive(Debug, thiserror::Error)]
pub enum TpmStorageError{
    #[error("Cannot access the TPM Device")]
    DeviceUnavailableError,
    #[error("Cannot connect to the TPM. Reason: {0}")]
    StartupError(String),
    #[error("Cannot create the key. Reason: {0}")]
    KeyGenerationError(String),
    #[error("Key not found")]
    KeyNotFound,
    #[error("Bad input value: {0:?}")]
    BadInput(BadInput),
    #[error("Unexpected error: {0}")]
    UnexpectedBehaviour(String),
    #[error("Error encountered during sign operation: {0}")]
    SignatureError(String)
}

#[derive(Debug)]
pub enum BadInput{
    KeyType,
    InputSize(String),
    SignatureAlgorithm,
    Jwk
}

impl std::fmt::Display for BadInput{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BadInput::KeyType => f.write_str("KeyType"),
            BadInput::InputSize(input) => f.write_fmt(format_args!("Input size of {}", input)),
            BadInput::SignatureAlgorithm => f.write_str("signature algorithm"),
            BadInput::Jwk => f.write_str("malformed Jwk")
        }
    }
}