---
layout: default
title: Model
parent: Components
nav_order: 4
---

# Model crate (`wazuh-cert-oauth2-model`)

This crate bundles shared code (models, services, helpers) that the server, webhook, and client reuse.

## Logging helper

`services/logging.rs` exposes `setup_logging(service_name: &str)`, which installs a basic `tracing_subscriber::fmt()` subscriber. `RUST_LOG` controls filtering (defaults to `info` if unset). Example: `info,rocket=warn,reqwest=warn`.

```rust
use wazuh_cert_oauth2_model::services::logging::setup_logging;

fn main() -> anyhow::Result<()> {
    setup_logging("my-service")?;
    // …
    Ok(())
}
```

## Other shared services

| Service | Purpose |
| :--- | :--- |
| `services/http_client.rs` | Tuned `reqwest` client helper with pooling/timeouts. |
| `services/jwks.rs` | JWKS/discovery caching utilities (when compiled with the `rocket` feature). |
