---
layout: default
title: Server
parent: Components
nav_order: 1
---

# Certificate Server (`wazuh-cert-oauth2-server`)

The central backend that validates OIDC tokens, signs CSRs using a Root CA, and manages the Certificate Revocation List (CRL).

## Purpose

- Signs agent CSRs using an issuing CA.
- Maintains a ledger of issued/revoked certificates (CSV on disk).
- Rebuilds and serves the CRL.
- Validates incoming requests with OIDC (discovery + JWKS), with optional audience checks.

## Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Liveness probe. |
| `GET` | `/crl/issuing.crl` | Current CRL as `application/pkix-crl`. |
| `GET` | `/api/revocations` | JSON view of revoked entries (auth required). |
| `POST` | `/api/revoke` | Revoke by serial or subject; triggers CRL rebuild (auth required). |
| `POST` | `/api/register-agent` | Sign CSR and return signed cert + CA (auth required). |

## Certificate contents

- **Subject CN**: set to the JWT subject (`sub`).
- **SANs**:
  - DNS entry mirroring CN for compatibility.
  - URI binding issuer realm + subject: `{iss}#sub={sub}`. Example: `https://kc.example/realms/foo#sub=1234-...`.
- **Key usage**: digital signature (+ key encipherment for RSA).
- **EKU**: `clientAuth`.

## Configuration

| Flag | Env Variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `--oauth-issuer` | `OAUTH_ISSUER` | (required) | OIDC issuer URL. |
| `--kc-audiences` | `KC_AUDIENCES` | (optional) | Comma-separated audiences for JWT validation. |
| `--root-ca-path` | `ROOT_CA_PATH` | (required) | PEM CA cert path. |
| `--root-ca-key-path` | `ROOT_CA_KEY_PATH` | (required) | PEM CA private key path. |
| `--discovery-ttl-secs` | `DISCOVERY_TTL_SECS` | `3600` | OIDC discovery cache TTL. |
| `--jwks-ttl-secs` | `JWKS_TTL_SECS` | `300` | JWKS cache TTL. |
| `--ca-cache-ttl-secs` | `CA_CACHE_TTL_SECS` | `300` | CA cert/key cache TTL. |
| `--crl-dist-url` | `CRL_DIST_URL` | (optional) | CDP URL to embed in issued certs. |
| `--crl-path` | `CRL_PATH` | `/data/issuing.crl` | CRL file path to write. |
| `--ledger-path` | `LEDGER_PATH` | `/data/ledger.csv` | Issued/revoked ledger path. |
| `--webhook-base-url` | `WEBHOOK_BASE_URL` | (optional) | Base URL of the webhook (for eviction notifications). |
| `--webhook-bearer-token` | `WEBHOOK_BEARER_TOKEN` | (optional) | Bearer token for the webhook. |

## Data and persistence

Mount a writable volume at `/data` (or adjust paths) so the CRL and ledger persist.

### Ledger fields

CSV columns: `subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason,issuer,realm`.

`issuer` and `realm` are optional; older rows may omit them and are handled gracefully.

## Logging

`tracing_subscriber` is initialized automatically; logs go to stdout. Control verbosity with `RUST_LOG` (e.g. `info,rocket=warn,reqwest=warn`). Defaults to `info` if unset.

```bash
wazuh-cert-oauth2-server --help
```

## Operational guidance

- Issue one certificate per installed agent (machine) and one per human user (UI/API).
- Never share client certificates across users or machines.
- Use ledger lookups by subject or serial for fast ban/revocation decisions.
