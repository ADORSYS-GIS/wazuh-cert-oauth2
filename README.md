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
- **Nginx sidecar image**: CRL-validating proxy for agent enrollment traffic, consumed by the Wazuh Helm chart — see `.docker/nginx-sidecar/` and [Getting Started](docs/getting-started.md#nginx-sidecar-image).

Internal utilities: `wazuh-cert-oauth2-healthcheck`.

## Quick start

- **Documentation**: Browse the full feature documentation on the [GitHub Pages site](https://adorsys-gis.github.io/wazuh-cert-oauth2/) (built with Jekyll/Just the Docs from the `docs/` folder).

- For detailed setup instructions, prerequisites, and a guide on running the project locally, please see the [Getting Started Guide](docs/getting-started.md).

- **Docker Compose Stack**:
  - `docker compose up -d --build`
  - Server: `http://localhost:8000`
  - Webhook: `http://localhost:8100`
  - Keycloak: `http://localhost:9100`

- **Getting Started Guide**: See [Getting Started](docs/getting-started.md).


## Documentation (local preview)

The docs site is built with Jekyll and the Just-the-Docs theme (see [`_config.yml`](_config.yml) and `_includes/`). You don't need Ruby installed — previewing runs in Docker:

```bash
make -f Makefile.docs docs-serve   # live-reload preview at http://localhost:4000/wazuh-cert-oauth2/
make -f Makefile.docs docs-build   # one-off static build into ./_site
make -f Makefile.docs docs-clean   # remove build output and the Docker gem cache
```

`docs-serve` caches the Ruby gems in a Docker named volume, so only the first run is slow.

## License

MIT — see `LICENSE`.
