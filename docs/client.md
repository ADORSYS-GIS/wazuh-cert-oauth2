---
layout: default
title: Client
parent: Components
nav_order: 2
---

# Wazuh Agent Client (`wazuh-cert-oauth2-client`)

A CLI tool run on the Wazuh agent host. It handles user authentication via OIDC, CSR generation, and submission to the backend.

## Purpose

- Runs on an end host to obtain a signed certificate for the Wazuh agent via OAuth2.
- Supports OIDC: discovers endpoints, fetches JWKS, obtains and validates a token.
- Automates the end-to-end flow (optional): stop agent, generate key + CSR, submit CSR, save cert/key (and CA), set agent name, restart agent.

## Typical flow

1. Discover OIDC endpoints from `--issuer`.
2. Fetch JWKS and obtain a token (service-account or user flow depending on `--is-service-account` and `--client-secret`).
3. Validate token and extract the name claim.
4. Generate keypair and CSR (subject derived from token `sub`).
5. Submit CSR to the server `--endpoint` with Bearer auth.
6. Save certificate, private key, and CA certificate to paths.
7. Optionally stop/restart the Wazuh agent and set the agent name.

## Configuration

| Flag | Env Variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `--issuer` | `ISSUER` | `https://login.wazuh.adorsys.team/realms/adorsys` | OIDC issuer. |
| `--audience` | `AUDIENCE` | `account` | Target audience(s). |
| `--client-id` | `CLIENT_ID` | `adorsys-machine-client` | OAuth2 client id. |
| `--client-secret` | `CLIENT_SECRET` | (none) | Optional client secret (enables client-credentials flow). |
| `--endpoint` | `ENDPOINT` | `https://cert.wazuh.adorsys.team/api/register-agent` | Server endpoint for CSR submission. |
| `--is-service-account` | `IS_SERVICE_ACCOUNT` | `false` | Whether the token subject is a service account. |
| `--cert-path` | `CERT_PATH` | platform default | Destination cert path. |
| `--key-path` | `KEY_PATH` | platform default | Destination key path. |
| `--agent-control` | `AGENT_CONTROL` | `true` | Perform stop/set-name/restart. |

```bash
wazuh-cert-oauth2-client --help
```
