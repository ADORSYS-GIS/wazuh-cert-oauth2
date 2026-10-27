---
layout: default
title: Model
parent: Components
nav_order: 4
---

# Model crate (`wazuh-cert-oauth2-model`)

This crate bundles shared code — **models**, **services**, and **helpers** — reused across the server, webhook, and client. It keeps the data contracts and cross-cutting concerns in one place so each binary doesn't redefine them.

## Data models (`models/`)

| Module | Purpose |
| :--- | :--- |
| `claims.rs` | Parsed OIDC JWT claims (`sub`, `name`, `iss`, `exp`, `preferred_username`, realm roles). Helpers: `get_name()` (prefers `name`, falls back to `preferred_username`) and `is_admin()` (checks the `wazuh_admin` role). |
| `document.rs` | OIDC `DiscoveryDocument` (issuer, authorization/token endpoints, `jwks_uri`); unknown fields are captured for forward compatibility. |
| `ledger_entry.rs` | One row of the issuance ledger: `subject`, `serial_hex`, `issued_at_unix`, `revoked`, optional `revoked_at_unix`/`reason`/`issuer`/`realm`, and `wazuh_agent_name`. |
| `sign_csr_request.rs` | CSR submission payload: `csr_pem`, optional `overwrite`, optional `wazuh_agent_name`. |
| `signed_cert_response.rs` | Server response: `certificate_pem` + `ca_cert_pem`. |
| `revoke_request.rs` | Revocation payload: optional `serial_hex` / `subject` / `reason`. |
| `user_representation.rs` | Simplified Keycloak user representation (`id`, `enabled`, `username`, `email`, names) used for event filtering. |
| `errors.rs` | Unified `AppError` / `AppResult` covering I/O, HTTP, upstream, conflict, validation, serialization, JWT, and more, with Rocket `Responder` support. |

## Services (`services/`)

| Module | Purpose |
| :--- | :--- |
| `logging.rs` | `setup_logging(service_name)` installs a `tracing_subscriber::fmt()` subscriber; `RUST_LOG` controls verbosity (defaults to `info`). |
| `http_client.rs` | Tuned `reqwest` client helper with connection pooling and timeouts. |
| `jwks.rs` | JWKS / OIDC discovery caching utilities (compiled with the `rocket` feature). |
| `wazuh.rs` | Client for the **Wazuh Manager REST API** (auth, agent lookup/eviction), used by the webhook's eviction pipeline. |
| `otel.rs` | OpenTelemetry setup — `init_tracer_provider` / `init_meter_provider` for tracing and metrics. |

## Feature flags

- `rocket` — gates the `logging` service (for Rocket-based binaries).

## Usage

```rust
use wazuh_cert_oauth2_model::services::logging::setup_logging;

fn main() -> anyhow::Result<()> {
    setup_logging("my-service")?;
    // …
    Ok(())
}
```
