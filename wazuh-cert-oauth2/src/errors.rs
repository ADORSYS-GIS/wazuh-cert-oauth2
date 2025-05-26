#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("RocketError reported error: {source}")]
    RocketError {
        #[from]
        source: rocket::Error,
    },
}