use rocket::Request;
use rocket::http::Status;
use rocket::response::{Responder, Response};
use rocket::serde::json::Json;
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    // Generic
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Upstream error: {0}")]
    UpstreamError(String),

    #[cfg(feature = "postgres")]
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),

    #[error("UTF-8 conversion error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),

    #[error("Invalid integer: {0}")]
    ParseInt(#[from] std::num::ParseIntError),

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

    #[error("OAuth2 HTTP error: {0}")]
    OAuth2Error(#[from] oauth2::http::Error),

    #[error("OAuth2 configuration error: {0}")]
    ConfigurationError(#[from] oauth2::ConfigurationError),

    #[error("OAuth2 request token error: {0}")]
    RequestTokenError(
        #[from]
        oauth2::RequestTokenError<
            oauth2::HttpClientError<reqwest::Error>,
            oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
        >,
    ),

    #[error("URL parse error: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[cfg(feature = "openssl")]
    #[error("OpenSSL error: {0}")]
    ErrorStack(#[from] openssl::error::ErrorStack),

    #[error("JSON parse error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Rand OS generation error: {0}")]
    RandOsError(#[from] rand::rngs::SysError),

    #[cfg(feature = "rocket")]
    #[error("SetGlobalDefaultError: {source}")]
    SetGlobalDefaultError {
        #[from]
        source: tracing::dispatcher::SetGlobalDefaultError,
    },

    // CRL / OpenSSL FFI
    #[error("CRL/OpenSSL FFI error in {func}")]
    CrlFfi { func: &'static str },
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl AppError {
    /// Map an error to the HTTP status code it should be served with.
    ///
    /// Extracted from the `Responder` impl so the mapping is unit-testable
    /// without constructing a Rocket `Request`.
    fn status(&self) -> Status {
        match &self {
            AppError::UpstreamError(_) => Status::BadGateway,
            #[cfg(feature = "postgres")]
            AppError::DatabaseError(_) => Status::BadGateway,
            AppError::Conflict(_) => Status::Conflict,
            AppError::RequestTokenError(_) => Status::ServiceUnavailable,
            AppError::CsrMissingPublicKey
            | AppError::SerdeError(_)
            | AppError::CsrVerificationFailed
            | AppError::KeyPolicyRsaTooSmall { .. }
            | AppError::KeyPolicyUnsupportedEcCurve { .. }
            | AppError::KeyPolicyUnknownEcCurve
            | AppError::KeyPolicyUnsupportedKeyType { .. }
            | AppError::ValidationError(_) => Status::BadRequest,
            _ => Status::InternalServerError,
        }
    }
}

impl<'r> Responder<'r, 'static> for AppError {
    fn respond_to(self, req: &'r Request<'_>) -> Result<Response<'static>, Status> {
        let message = self.to_string();

        let status = self.status();

        if status == Status::InternalServerError {
            tracing::error!("Internal server error: {}", message);
        }

        // Avoid leaking internal details (program names, FFI function names, etc.)
        // for server-side errors. Client-facing errors (4xx) pass through as-is.
        let client_message = if status.code >= 500 && status != Status::ServiceUnavailable {
            "An internal error occurred".to_string()
        } else {
            message
        };

        let json = Json(ErrorResponse {
            error: client_message,
        });

        Response::build_from(json.respond_to(req)?)
            .status(status)
            .ok()
    }
}

// Convenience alias used where appropriate
pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::AppError;
    use rocket::http::Status;

    #[test]
    fn validation_error_maps_to_bad_request() {
        assert_eq!(
            AppError::ValidationError("bad".into()).status(),
            Status::BadRequest
        );
    }

    #[test]
    fn conflict_maps_to_conflict() {
        assert_eq!(AppError::Conflict("dup".into()).status(), Status::Conflict);
    }

    #[test]
    fn upstream_error_maps_to_bad_gateway() {
        assert_eq!(
            AppError::UpstreamError("up".into()).status(),
            Status::BadGateway
        );
    }

    #[test]
    fn csr_and_key_policy_errors_map_to_bad_request() {
        assert_eq!(AppError::CsrMissingPublicKey.status(), Status::BadRequest);
        assert_eq!(AppError::CsrVerificationFailed.status(), Status::BadRequest);
        assert_eq!(
            AppError::KeyPolicyRsaTooSmall { bits: 1024 }.status(),
            Status::BadRequest
        );
        assert_eq!(
            AppError::KeyPolicyUnsupportedEcCurve { nid: "x".into() }.status(),
            Status::BadRequest
        );
        assert_eq!(
            AppError::KeyPolicyUnknownEcCurve.status(),
            Status::BadRequest
        );
        assert_eq!(
            AppError::KeyPolicyUnsupportedKeyType {
                key_type: "x".into()
            }
            .status(),
            Status::BadRequest
        );
    }

    #[test]
    fn serde_error_maps_to_bad_request() {
        assert_eq!(
            AppError::SerdeError(serde_json::from_str::<u8>("nope").unwrap_err()).status(),
            Status::BadRequest
        );
    }

    #[test]
    fn io_error_maps_to_internal_server_error() {
        let err = AppError::Io(std::io::Error::other("boom"));
        assert_eq!(err.status(), Status::InternalServerError);
    }

    #[test]
    fn request_token_error_maps_to_service_unavailable() {
        use oauth2::basic::BasicErrorResponseType;
        use oauth2::{RequestTokenError, StandardErrorResponse};

        let response =
            StandardErrorResponse::new(BasicErrorResponseType::InvalidRequest, None, None);
        let err = AppError::RequestTokenError(RequestTokenError::ServerResponse(response));
        assert_eq!(err.status(), Status::ServiceUnavailable);
    }

    #[test]
    fn display_messages_are_human_readable() {
        assert_eq!(
            AppError::ValidationError("bad".into()).to_string(),
            "Validation error: bad"
        );
        assert_eq!(
            AppError::Conflict("dup".into()).to_string(),
            "Conflict: dup"
        );
        assert_eq!(
            AppError::CsrMissingPublicKey.to_string(),
            "CSR missing public key"
        );
        assert_eq!(
            AppError::KeyPolicyRsaTooSmall { bits: 1024 }.to_string(),
            "RSA key too small: 1024 bits (min 2048)"
        );
        assert_eq!(
            AppError::KeyPolicyUnsupportedKeyType {
                key_type: "Ed25519".into()
            }
            .to_string(),
            "Unsupported key type: Ed25519"
        );
    }
}
