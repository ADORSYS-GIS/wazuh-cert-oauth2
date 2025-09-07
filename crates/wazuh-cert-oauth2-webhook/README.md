# Wazuh Certificate OAuth2 Webhook

Purpose

- Receives webhooks from the OIDC/IdP (e.g., Keycloak) and translates them into certificate revocations.
- Forwards revocation requests to the server with retry and persistent spooling.
- Supports multiple inbound auth options for the webhook endpoint (Basic, Bearer, API key, or anonymous when none configured).
- Can acquire an OAuth2 client-credentials token (or use a static bearer) to call the server.
- Future: optionally disable Wazuh agent on revoke (not yet implemented).

Endpoints

- `GET /health`: liveness probe.
  (All metrics are exported via OTLP; no Prometheus endpoint.)
- `POST /api/webhook`: receives IdP event payloads; will ignore, revoke, or cancel queued revokes depending on event type/body.

Configuration

- `--server-base-url` (`SERVER_BASE_URL`): Base URL of the server (required), e.g. `https://cert.wazuh.example`.
- `--spool-dir` (`SPOOL_DIR`, default `/data/spool`): Directory for queued revoke requests.
- `--retry-attempts` (`RETRY_ATTEMPTS`, default 5): Max retry attempts per revoke.
- `--retry-base-ms` (`RETRY_BASE_MS`, default 500): Initial backoff.
- `--retry-max-ms` (`RETRY_MAX_MS`, default 8000): Maximum backoff.
- `--spool-interval-secs` (`SPOOL_INTERVAL_SECS`, default 10): Interval between spool scans.
- `--proxy-bearer-token` (`PROXY_BEARER_TOKEN`): Static bearer token for calls to the server (mutually exclusive with OAuth2).
- `--oauth-issuer` (`OAUTH_ISSUER`): OIDC issuer for discovery (optional; used to get tokens for server).
- `--oauth-client-id` (`OAUTH_CLIENT_ID`): OAuth client id.
- `--oauth-client-secret` (`OAUTH_CLIENT_SECRET`): OAuth client secret.
- `--oauth-scope` (`OAUTH_SCOPE`): Optional scope.
- `--oauth-audience` (`OAUTH_AUDIENCE`): Optional audience.
- `--keycloak-revoke-reason` (`KEYCLOAK_REVOKE_REASON`, default `Keycloak event`): Reason string attached to server revoke requests.
- Inbound webhook auth (any set are accepted):
  - `--webhook-basic-user` (`WEBHOOK_BASIC_USER`)
  - `--webhook-basic-password` (`WEBHOOK_BASIC_PASSWORD`)
  - `--webhook-api-key` (`WEBHOOK_API_KEY`)
  - `--webhook-bearer-token` (`WEBHOOK_BEARER_TOKEN`)

Data and persistence

- Mount a writable volume at `/data` (or adjust `--spool-dir`) for durable spooling.

Telemetry (OTel + tracing)

- Tracing: OTLP/gRPC exporter (gzip, 3s timeout).
- Metrics: OTLP metrics export (3s interval). No `/metrics` endpoint.
- HTTP request spans via Rocket fairing (request start log).
- Outbound propagation: W3C trace context headers injected into `reqwest` calls to the server.
- Spool/retry logic, webhook handlers, and state paths are instrumented.
- Service name: `wazuh-cert-oauth2-webhook`.

Telemetry env vars (gRPC only)

- `RUST_LOG`: e.g. `info,rocket=warn,reqwest=warn`.
- `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://localhost:4317`): base OTLP endpoint for traces and metrics.
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (optional): override traces endpoint.
- `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` (optional): override metrics endpoint.
- `OTEL_EXPORTER_OTLP_PROTOCOL` (default `grpc`): protocol used. Only `grpc` is supported; HTTP/JSON or HTTP/Protobuf exporters are not supported.
- `OTEL_EXPORTER_OTLP_HEADERS` (optional): additional headers (e.g., auth) to the collector.
- `OTEL_RESOURCE_ATTRIBUTES` (optional): comma‑separated resource attributes (e.g., `service.version=0.2.20,deployment.environment=prod`).

Metrics endpoint examples (gRPC)

```bash
# Same collector for traces + metrics (default OTLP/gRPC port 4317)
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4317

# Or split per signal (still gRPC)
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://otel-collector:4317
export OTEL_EXPORTER_OTLP_METRICS_ENDPOINT=http://otel-collector:4317

# Optional auth header to collector
export OTEL_EXPORTER_OTLP_HEADERS="authorization=Bearer <token>"
```

Quick start

```bash
export RUST_LOG=info,rocket=warn,reqwest=warn
export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317

wazuh-cert-oauth2-webhook \
  --server-base-url https://cert.wazuh.example \
  --oauth-issuer https://issuer.example/realms/xyz \
  --oauth-client-id my-client \
  --oauth-client-secret ...
```
