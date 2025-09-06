# Wazuh Certificate OAuth2 Server

Purpose

- Signs agent CSRs using an issuing CA.
- Maintains a ledger of issued/revoked certificates (CSV on disk).
- Rebuilds and serves the CRL.
- Validates incoming requests with OIDC (discovery + JWKS), optional audience checks.

Endpoints

- `GET /health`: liveness probe.
- `GET /crl/issuing.crl`: current CRL as `application/pkix-crl`.
- `GET /api/revocations`: JSON view of revoked entries (auth required).
- `POST /api/revoke`: revoke by serial or subject; triggers CRL rebuild (auth required).
- `POST /api/register-agent`: sign CSR and return signed cert + CA (auth required).
  (All metrics are exported via OTLP; no Prometheus endpoint.)

Configuration

- `--oauth-issuer` (`OAUTH_ISSUER`): OIDC issuer URL (required).
- `--kc-audiences` (`KC_AUDIENCES`): comma-separated audiences for JWT validation (optional).
- `--root-ca-path` (`ROOT_CA_PATH`): PEM CA cert path (required).
- `--root-ca-key-path` (`ROOT_CA_KEY_PATH`): PEM CA private key path (required).
- `--discovery-ttl-secs` (`DISCOVERY_TTL_SECS`, default 3600): OIDC discovery cache TTL.
- `--jwks-ttl-secs` (`JWKS_TTL_SECS`, default 300): JWKS cache TTL.
- `--ca-cache-ttl-secs` (`CA_CACHE_TTL_SECS`, default 300): CA cert/key cache TTL.
- `--crl-dist-url` (`CRL_DIST_URL`): optional CDP URL to embed in issued certs.
- `--crl-path` (`CRL_PATH`, default `/data/issuing.crl`): CRL file path to write.
- `--ledger-path` (`LEDGER_PATH`, default `/data/ledger.csv`): issued/revoked ledger path.

Data and persistence

- Mount a writable volume at `/data` (or adjust paths) so CRL and ledger persist.

Telemetry (OTel + tracing)

- Tracing: OTLP/gRPC exporter (gzip, 3s timeout).
- Metrics: OTLP metrics export (3s interval). No `/metrics` endpoint.
- HTTP request spans via Rocket fairing, logs start/end with method/path/status/bytes.
- Outbound propagation: W3C trace context headers injected into `reqwest` calls.
- Service name: `wazuh-cert-oauth2-server`.

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

wazuh-cert-oauth2-server \
  --oauth-issuer https://issuer.example.com/realms/xyz \
  --root-ca-path /data/issuing.pem \
  --root-ca-key-path /data/issuing.key
```
