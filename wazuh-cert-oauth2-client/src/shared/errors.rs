use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("App reported error: {source}")]
    AnyError {
        #[from]
        source: anyhow::Error,
    },

    #[error("Kubernetes reported error: {source}")]
    StdError {
        #[from]
        source: io::Error,
    },
}