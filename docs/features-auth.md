---
layout: default
title: Authentication (OIDC / OAuth2)
parent: Features
nav_order: 1
---

# Authentication (OIDC / OAuth2)

Agents authenticate through an industry-standard **OIDC / OAuth2** identity provider such as Keycloak, rather than static shared credentials. A short-lived token proves identity at enrollment time; the signed mTLS client certificate is the long-term credential.

## How the client authenticates

The `wazuh-cert-oauth2-client` runs on the agent host and drives the flow end-to-end:

1. **Discover endpoints**: fetch `.well-known/openid-configuration` from `--issuer` to locate the authorization, token, and JWKS endpoints.
2. **Fetch JWKS**: retrieve the provider's JSON Web Key Set, used to validate tokens.
3. **Authenticate**: obtain a token using one of two modes:
   - **User flow**: the client prints an authorization URL (and opens the browser automatically if possible); after login it receives an authorization code and exchanges it for an access token (RFC 8252–style `+` localhost callback).
   - **Client-credentials flow** (service account): used when `--client-secret` is set and the token subject is a service account.
4. **Validate**: verify the JWT signature against the JWKS, plus audience and expiry, before submitting any CSR.

## How the server validates requests

- The server discovers the issuer and **fetches JWKS** (with caching, see `--discovery-ttl-secs` / `--jwks-ttl-secs`).
- Every protected endpoint (CSR signing, revocation, ledger queries) requires a valid OIDC bearer token.
- **Audience checks** are optional (`--kc-audiences`); when set, only tokens carrying an expected audience are accepted.

## Key points

- **No shared secrets**: each enrollment proves identity via the IdP, so there are no long-lived static per-agent credentials.
- **Per-subject identity**: the certificate's subject and identity URI SAN are bound to the token's `sub` claim.
- **Two authentication modes**: interactive (user) and machine (client-credentials) flows cover both human and automated enrollment.
