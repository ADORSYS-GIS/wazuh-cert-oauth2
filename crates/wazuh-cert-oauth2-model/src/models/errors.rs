#[derive(Debug, thiserror::Error)]
pub enum AppError {
    // Generic
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Upstream error: {0}")]
    UpstreamError(String),

    #[error("Random error: {0}")]
    Serialization(String),

    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    // JWT / OIDC
    #[error("JWT error: {0}")]
    JwtError(#[from] jsonwebtoken::errors::Error),

    #[error("JWT header missing 'kid'")]
    JwtMissingKid,

    #[error("JWT payload missing 'name'")]
    JwtMissingName,

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
    #[error("Rocket error: {0}")]
    RocketError(#[from] Box<rocket::Error>),

    #[error("CLI error: {0}")]
    CliError(#[from] clap::Error),

    #[error("OAuth2 Error error: {0}")]
    OAuth2Error(#[from] oauth2::http::Error),

    #[error("Configuration Error error: {0}")]
    ConfigurationError(#[from] oauth2::ConfigurationError),

    #[error("Basic auth request error: {0}")]
    RequestTokenError(
        #[from]
        oauth2::RequestTokenError<
            oauth2::HttpClientError<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ),

    #[error("URL Parse Error error: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[cfg(feature = "openssl")]
    #[error("URL Parse Error error: {0}")]
    ErrorStack(#[from] openssl::error::ErrorStack),

    #[error("Parse JSON Error error: {0}")]
    SerdeError(#[from] serde_json::Error),

    //#[error("Random generation error: {0}")]
    //RandOsError(#[from] rand_core::Error),
    #[error("Rand OS generation error: {0}")]
    RandOsError(#[from] rand_core::OsError),

    #[cfg(feature = "rocket")]
    #[error("SetGlobalDefaultError error: {source}")]
    SetGlobalDefaultError {
        #[from]
        source: tracing::dispatcher::SetGlobalDefaultError,
    },

    // CRL / OpenSSL FFI
    #[error("CRL/OpenSSL FFI error in {func}")]
    CrlFfi { func: &'static str },
}

// Convenience alias used where appropriate
pub type AppResult<T> = Result<T, AppError>;
