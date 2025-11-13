# Telemetry Helpers (model crate)

This crate provides shared telemetry setup for the workspace.

What it provides

- `services/otel.rs` exports `setup_telemetry(service_name: &str)` which:
  - Sets up an OTLP/gRPC exporter for traces with gzip compression and a 3s timeout.
  - Sets up an OTLP metrics exporter with a periodic reader (3s interval).
  - Installs a `tracing_subscriber` with `EnvFilter` (uses `RUST_LOG`) and a fmt layer.
  - Exports metrics via OTLP only; no Prometheus scraping endpoint.

Environment variables (gRPC only)

Standard OpenTelemetry variables are honored by the OTLP exporters:

- `RUST_LOG`: tracing filter (e.g. `info,rocket=warn,reqwest=warn`).
- `OTEL_EXPORTER_OTLP_ENDPOINT` (default: `http://localhost:4317`): base OTLP endpoint for traces and metrics.
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (optional): override traces endpoint.
- `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` (optional): override metrics endpoint.
- `OTEL_EXPORTER_OTLP_PROTOCOL` (default: `grpc`): Protocol for OTLP export. Only `grpc` is supported; HTTP/JSON or HTTP/Protobuf exporters are not supported.
- `OTEL_EXPORTER_OTLP_HEADERS` (optional): Additional headers (e.g., auth) for the exporter.
- `OTEL_RESOURCE_ATTRIBUTES` (optional): comma‑separated resource attributes (e.g., `service.version=0.2.22,deployment.environment=prod`).

Implementation defaults (code-controlled)

- Export timeout: 3s for traces and metrics.
- Export compression: gzip.
- Metrics export interval: 3s periodic reader.
- Service name: passed by the caller (`setup_telemetry("…")`).

Propagation

- `services/http_client.rs` injects W3C Trace Context headers into outbound `reqwest` requests so downstream services can join the trace.

Usage

```rust
use wazuh_cert_oauth2_model::services::otel::setup_telemetry;

fn main() -> anyhow::Result<()> {
    setup_telemetry("my-service")?;
    // …
    Ok(())
}
```

Collector configuration examples

```bash
# Single collector endpoint
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317

# Optional: separate endpoints per signal
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://otel-collector:4317
export OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://otel-collector:4317

# Optional: auth header
export OTEL_EXPORTER_OTLP_HEADERS="authorization=Bearer <token>"
```
