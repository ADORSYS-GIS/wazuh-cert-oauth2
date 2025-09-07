pub mod http_client;
pub mod jwks;

#[cfg(feature = "rocket")]
pub mod otel;

// metrics endpoint removed (OTLP only)
