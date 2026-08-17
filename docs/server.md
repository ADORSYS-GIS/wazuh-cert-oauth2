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
- Maintains a ledger of issued/revoked certificates (PostgreSQL, or CSV as a local-dev fallback).
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
| `--crl-path` | `CRL_PATH` | `/data/issuing.crl` | CRL file path to write (local-dev fallback). |
| `--ledger-path` | `LEDGER_PATH` | `/data/ledger.csv` | CSV ledger path (local-dev fallback). |
| `--database-url` | `DATABASE_URL` | (optional) | PostgreSQL DSN. When set, the ledger uses PostgreSQL as the system of record; otherwise it falls back to the CSV ledger at `LEDGER_PATH`. |
| `--webhook-base-url` | `WEBHOOK_BASE_URL` | (optional) | Base URL of the webhook (for eviction notifications). |
| `--webhook-bearer-token` | `WEBHOOK_BEARER_TOKEN` | (optional) | Bearer token for the webhook. |

## Data and persistence

The ledger backend is configurable:

- **PostgreSQL (recommended for multi-replica):** set `DATABASE_URL`. The server
  applies `sqlx` migrations on startup and stores the ledger in two tables —
  `ledger_event` (append-only audit log) and `ledger_entry` (materialized current
  state). This is the system of record and enables running multiple server
  replicas against a shared database.
- **CSV (local-dev / emergency fallback):** when `DATABASE_URL` is unset, the
  server uses the on-disk CSV ledger at `LEDGER_PATH`.

Mount a writable volume at `/data` (or adjust paths) so the CRL and CSV ledger
persist when using the fallback backend.

### CRL

The CRL is a **derived artifact**: it is rebuilt from the ledger's revoked
entries (`ledger_entry WHERE revoked = true`) and served from
`GET /crl/issuing.crl` with ETag / long-poll support.

- **PostgreSQL backend:** the signed CRL (DER + ETag + a generation counter) is
  stored in the shared `crl_cache` table. Any replica may rebuild on demand; a
  `NOTIFY crl_changed` signal tells the other replicas to drop their local cache
  and serve the fresh CRL, so all replicas stay consistent after a revocation.
- **File fallback:** when `DATABASE_URL` is unset, the CRL is written to
  `CRL_PATH` (local-dev / bootstrap only).

The S3 init container and nginx file-serving sidecar are no longer on the
critical path; they are optional/archival for deployments that still want an
external CRL copy.

### Ledger fields

CSV columns: `subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason,issuer,realm`.

`issuer` and `realm` are optional; older rows may omit them and are handled gracefully.

### One-time CSV → PostgreSQL import

To migrate an existing CSV ledger into PostgreSQL, run the `import-ledger`
subcommand (applies migrations and bulk-inserts into both tables in a single
transaction):

```bash
INPUT_LEDGER_PATH=/data/ledger.csv DATABASE_URL=postgres://... wazuh-cert-oauth2-server import-ledger
```

## Logging

`tracing_subscriber` is initialized automatically; logs go to stdout. Control verbosity with `RUST_LOG` (e.g. `info,rocket=warn,reqwest=warn`). Defaults to `info` if unset.

```bash
wazuh-cert-oauth2-server --help
```

## Operational guidance

- Issue one certificate per installed agent (machine) and one per human user (UI/API).
- Never share client certificates across users or machines.
- Use ledger lookups by subject or serial for fast ban/revocation decisions.
