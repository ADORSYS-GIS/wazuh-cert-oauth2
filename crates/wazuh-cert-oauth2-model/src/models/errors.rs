#[derive(Debug, thiserror::Error)]
pub enum AppError {
    // Generic
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    // JWT / OIDC
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("JWT header missing 'kid'")]
    JwtMissingKid,

    #[error("No matching JWK found for kid: {0}")]
    JwtKeyNotFound(String),

    // CSR / X509 policy
    #[error("CSR missing public key")] 
    CsrMissingPublicKey,

    #[error("CSR verification failed")] 
    CsrVerificationFailed,

    #[error("RSA key too small: {bits} bits (min 2048)")]
    KeyPolicyRsaTooSmall { bits: usize },

    #[error("Unsupported EC curve: {nid} (only P-256 allowed)")]
    KeyPolicyUnsupportedEcCurve { nid: String },

    #[error("Unknown EC curve")] 
    KeyPolicyUnknownEcCurve,

    #[error("Unsupported key type: {key_type}")] 
    KeyPolicyUnsupportedKeyType { key_type: String },

    // External command execution
    #[error("Failed to spawn program '{program}': {err}")]
    CommandSpawn { program: String, err: String },

    #[error("Program '{program}' exited with non-zero status: {code:?}")]
    CommandFailed { program: String, code: Option<i32> },

    // Rocket (when enabled)
    #[cfg(feature = "rocket")]
    #[error("Rocket error: {source}")]
    RocketError { #[from] source: rocket::Error },

    // CRL / OpenSSL FFI
    #[error("CRL/OpenSSL FFI error in {func}")]
    CrlFfi { func: &'static str },
}

// Convenience alias used where appropriate
pub type AppResult<T> = Result<T, AppError>;
