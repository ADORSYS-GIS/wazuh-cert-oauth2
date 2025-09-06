# Wazuh Certificate OAuth2 Client

Purpose

- Runs on an end host to obtain a signed certificate for the Wazuh agent via OAuth2.
- Supports OIDC: discovers endpoints, fetches JWKS, obtains and validates a token.
- Automates the end-to-end flow (optional): stop agent, generate key + CSR, submit CSR, save cert/key (and CA), set agent name, restart agent.

Typical flow (OAuth2)

- Discover OIDC endpoints from `--issuer`.
- Fetch JWKS and obtain a token (service-account or user flow depending on `--is-service-account` and `--client-secret`).
- Validate token and extract the name claim.
- Generate keypair and CSR (subject derived from token `sub`).
- Submit CSR to the server `--endpoint` with Bearer auth.
- Save certificate, private key, and CA certificate to paths.
- Optionally stop/restart Wazuh agent and set the agent name.

CLI options (env mapped)

- `--issuer` (`ISSUER`): OIDC issuer (default `https://login.wazuh.adorsys.team/realms/adorsys`).
- `--audience` (`AUDIENCE`): target audience(s) (default `account`).
- `--client-id` (`CLIENT_ID`): OAuth2 client id (default `adorsys-machine-client`).
- `--client-secret` (`CLIENT_SECRET`): optional client secret (when set, client-credentials flow is used).
- `--endpoint` (`ENDPOINT`): server endpoint for CSR submission (default `https://cert.wazuh.adorsys.team/api/register-agent`).
- `--is-service-account` (`IS_SERVICE_ACCOUNT`, default false): whether the token subject is a service account.
- `--cert-path` (`CERT_PATH`): destination cert path (defaults to a sensible platform path).
- `--key-path` (`KEY_PATH`): destination key path (defaults to a sensible platform path).
- `--agent-control` (`AGENT_CONTROL`, default true): perform stop/set-name/restart.

Example

```bash
export RUST_LOG=info,reqwest=warn

wazuh-cert-oauth2-client oauth2 \
  --issuer https://issuer.example/realms/xyz \
  --client-id wazuh-client \
  --client-secret ... \
  --endpoint https://cert.wazuh.example/api/register-agent
```

Telemetry (optional)

- The CLI doesn’t initialize OpenTelemetry by default. If desired, call the shared initializer from `wazuh-cert-oauth2-model`:

```rust
use wazuh_cert_oauth2_model::services::otel::setup_telemetry;

fn main() -> anyhow::Result<()> {
    setup_telemetry("wazuh-cert-oauth2-client")?;
    Ok(())
}
```

Telemetry env vars (gRPC only)

- `RUST_LOG`: e.g. `info,reqwest=warn`.
- `OTEL_EXPORTER_OTLP_ENDPOINT` (default `http://localhost:4317`): base OTLP endpoint for traces and metrics.
- `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` (optional): override traces endpoint.
- `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` (optional): override metrics endpoint.
- `OTEL_EXPORTER_OTLP_PROTOCOL` (default `grpc`). Only `grpc` is supported; HTTP/JSON or HTTP/Protobuf exporters are not supported.
- `OTEL_EXPORTER_OTLP_HEADERS` (optional).
- `OTEL_RESOURCE_ATTRIBUTES` (optional): comma‑separated resource attributes (e.g., `service.version=0.2.20,deployment.environment=prod`).
