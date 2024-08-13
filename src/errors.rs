#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("App reported error: {source}")]
    AnyError {
        #[from]
        source: anyhow::Error,
    },

    #[error("Standard reported error: {source}")]
    StdError {
        #[from]
        source: std::io::Error,
    },

    #[error("RocketError reported error: {source}")]
    RocketError {
        #[from]
        source: rocket::Error,
    },

    #[error("NetworkError reported error: {source}")]
    NetworkError {
        #[from]
        source: reqwest::Error,
    },
}