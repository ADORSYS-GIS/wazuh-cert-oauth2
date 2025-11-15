# Wazuh Certificate OAuth2

[![Code Linting and SAST](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/ci.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/ci.yml)
[![Release Client](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/release.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/release.yml)
[![Helm Publish](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/helm-publish.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/helm-publish.yml)
[![Dependabot Updates](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/dependabot/dependabot-updates)
[![Build Docker image](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/build.yml/badge.svg)](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/actions/workflows/build.yml)

Minimal overview for the workspace. Each crate has its own detailed README.

## What is this?

Rust workspace providing certificate-based auth for Wazuh integrated with OAuth2/OIDC:

- Server: issues client certificates, keeps a ledger/CRL, and protects APIs with OIDC — see `crates/wazuh-cert-oauth2-server/README.md`.
- Client CLI: obtains a token, generates key + CSR, and registers the agent — see `crates/wazuh-cert-oauth2-client/README.md`.
- Webhook: consumes IdP events (e.g., Keycloak) and requests revocations — see `crates/wazuh-cert-oauth2-webhook/README.md`.
- Shared model helpers — see `crates/wazuh-cert-oauth2-model/README.md`.

Internal utilities: `wazuh-cert-oauth2-healthcheck`.

## Quick start

- Docker Compose (demo stack with Keycloak):
  - `docker compose up -d --build`
  - Server: `http://localhost:8000`, Webhook: `http://localhost:8100`

- Build from source:
  - `cargo build --release`
  - Example: `target/release/wazuh-cert-oauth2-server --oauth-issuer <url> --root-ca-path <pem> --root-ca-key-path <pem>`

## License

MIT — see `LICENSE`.
