use crate::models::errors::{AppError, AppResult};
use tracing_subscriber::EnvFilter;

/// Initialize a simple fmt subscriber so `tracing` macros emit logs.
/// Currently we just honor `RUST_LOG` via `EnvFilter` and write to stdout.
pub fn setup_logging(_service_name: &str) -> AppResult<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|source| AppError::SetGlobalDefaultError { source })?;
    Ok(())
}
