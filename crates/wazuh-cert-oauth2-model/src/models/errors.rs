#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("App reported error: {0}")]
    AnyError(anyhow::Error),

    #[error("Jwt error: {0}")]
    JwtError(jsonwebtoken::errors::Error),

    #[cfg(feature = "rocket")]
    #[error("RocketError reported error: {source}")]
    RocketError {
        #[from]
        source: rocket::Error,
    },
}
