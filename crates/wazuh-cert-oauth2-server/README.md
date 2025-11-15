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

Certificate contents

- Subject CN: set to the JWT subject (`sub`).
- SANs:
  - DNS entry mirroring CN for compatibility.
  - URI binding issuer realm + subject: `{iss}#sub={sub}`. Example: `https://kc.example/realms/foo#sub=1234-...`.
- Key usage: digital signature (+ key encipherment for RSA).
- EKU: clientAuth.

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

Ledger fields

- CSV columns: `subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason,issuer,realm`.
- `issuer` and `realm` are optional; older rows may omit them and are handled gracefully.

Logging

- `tracing_subscriber` is initialized automatically; logs are emitted to stdout.
- Control verbosity with `RUST_LOG` (e.g., `info,rocket=warn,reqwest=warn`). Defaults to `info` if unset.

Quick start

```bash
export RUST_LOG=info,rocket=warn,reqwest=warn

wazuh-cert-oauth2-server \
  --oauth-issuer https://issuer.example.com/realms/xyz \
  --root-ca-path /data/issuing.pem \
  --root-ca-key-path /data/issuing.key
```

Operational guidance

- Issue one certificate per installed agent (machine) and one per human user (UI/API).
- Never share client certificates across users or machines.
- Use ledger lookups by subject or serial for fast ban/revocation decisions.
