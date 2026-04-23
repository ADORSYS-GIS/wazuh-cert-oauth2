# Project Roadmap

This document outlines the future plans and development goals for the Wazuh Certificate OAuth2 project.

## Sprint Goals

### Cert-Oauth2-Webhook (proxy)
- **User Detection & Enrollment Tracking**: Automatically detect/count the number of users and identify those who aren't currently enrolled.
- **Automated Inactive Agent Removal**: Implement logic to automatically remove agents that have become inactive (e.g., when employees leave the company).
- **Multi-IdP Support**: Expand support to other identity providers beyond the current OIDC/Keycloak implementation.
- **Device Locking**: Implement "one cert per user" and "company-only device" restrictions.
    - Ensure each user can only have one active certificate.
    - Restrict enrollment and authentication to verified company devices.

### CLI/Native App OAuth Flow
- **OOB → PKCE + Localhost Migration**: Replace the deprecated OOB (`urn:ietf:wg:oauth:2.0:oob`) OAuth flow with PKCE + localhost redirect (per RFC 8252).
    - **Replace redirect URI**: Swap `urn:ietf:wg:oauth:2.0:oob` with `http://localhost:{port}/callback`. Register a loopback redirect in the OAuth app's allowed URIs (RFC 8252 §7.3 permits any port on loopback).
    - **Add PKCE**: Generate `code_verifier` (32 random bytes, base64url-encoded), derive `code_challenge = BASE64URL(SHA256(verifier))`, send `code_challenge` + `code_challenge_method=S256` in the authorization request, and include `code_verifier` in the token exchange.
    - **Spin up a local HTTP server**: Use a random port (port `0`) to avoid conflicts, start in a separate thread before opening the browser, capture the `code` query parameter from the callback, then shut down.
    - **Provider registration**: Add `http://localhost` (or `http://127.0.0.1`) as a loopback URI in the developer console. Some providers (Google, GitHub) require at least one registered loopback URI.

---

## Future Initiatives

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
