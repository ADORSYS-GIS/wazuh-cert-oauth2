# Security Next Steps

Focused, actionable remediations to harden the certificate‑signing server and webhook.

## High Priority

- Revoke authorization policy
  - Enforce self‑only or admin‑only revocation.
  - Self‑only: `subject == token.claims.sub`; for `serial_hex`, verify ownership via ledger.
  - Admin route: require admin claim/role; optionally split endpoints (`/api/revoke/self` vs `/api/revoke`).
  - File: `crates/wazuh-cert-oauth2-server/src/handlers/revoke.rs`.

- JWT issuer and algorithms
  - Require issuer: `validation.set_issuer(&[expected_issuer])`.
  - Restrict algorithms (e.g., RS256/PS256/ES256) rather than `Validation::new(header.alg)`.
  - Wire issuer from `OidcState` into `validate_token`.
  - Files: `.../model/src/services/jwks.rs`, `.../server/src/models/oidc_state.rs`, `.../server/src/handlers/middle.rs`.

- Audience validation
  - Default to audience validation in prod; add `--require-audience` flag (default true) and document.
  - Files: `.../model/src/services/jwks.rs`, `.../server/src/shared/opts.rs`, READMEs.

- Webhook auth mandatory
  - Fail startup if no webhook credential configured unless `--allow-anonymous-webhook` is set.
  - Files: `.../webhook/src/state/core.rs`, `.../webhook/src/state/builder.rs`, `.../webhook/src/handlers/auth.rs`.

## Medium Priority

- Normalize SAN identity URI
  - Embed `{iss}` without query/fragment; keep `{iss}#sub={sub}`.
  - File: `.../server/src/shared/certs/extensions.rs`.

- Request size/rate limits
  - Add Rocket JSON size limits; recommend proxy rate limits.
  - Files: `.../server/Rocket.toml`, deployment docs.

- CA key handling
  - Document 0600 perms + read‑only mount; optionally warn on permissive perms.
  - Files: `.../server/src/models/ca_config.rs`, README.

- Remove test CA artifacts
  - Quarantine `.docker/tmp/root-ca*.pem`; ensure they never ship in images; document as dev‑only.

- Logging hygiene
  - Avoid logging JWT headers at debug in prod; use trace or feature flag.
  - File: `.../model/src/services/jwks.rs`.

- SSRF/issuer sanity
  - Validate `--oauth-issuer` format; require `https://` in prod.

## Low Priority / Enhancements

- Cert validity policy
  - Consider 90–180 day certs if acceptable.
  - File: `.../server/src/shared/certs/build_base.rs`.

- Key policy flexibility
  - Optional: allow P‑384 with a clear policy toggle.
  - File: `.../server/src/shared/certs/policy.rs`.

- SAN DNS reconsideration
  - If clients don’t require DNS SAN, remove; keep URI SAN as primary identity.
  - File: `.../server/src/shared/certs/extensions.rs`.

## Implementation Checklist

- Revoke guard logic and tests: `revoke.rs`.
- Token validation wiring: `jwks.rs`, `oidc_state.rs`, `handlers/middle.rs`.
- SAN URI normalization: `extensions.rs`.
- Rocket limits: `Rocket.toml`.
- Webhook startup checks: `webhook` state/auth.
- Docs: audience requirement, revocation auth model, CA key perms, proxy limits, CRL ops.

## Validation

- Unit tests: revoke auth; issuer/alg enforcement; SAN normalization.
- Integration: CSR→issue→ledger→revoke→CRL contains serial; webhook auth paths.

