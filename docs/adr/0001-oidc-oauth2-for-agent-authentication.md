# ADR-0001: OIDC / OAuth2 for agent authentication

> Agents authenticate through an OIDC/OAuth2 identity provider (Keycloak) instead of static secrets.

## Metadata

| Field | Value |
| :--- | :--- |
| **Document ID** | ADR-0001 |
| **Status** | `Accepted` |
| **Date** | N/A |
| **Deciders** | Wazuh maintainers |
| **Governs** | crates/wazuh-cert-oauth2-server (auth), crates/wazuh-cert-oauth2-client |
| **Amends** | N/A |
| **Amended by** | N/A |
| **Supersedes** | N/A |
| **Superseded by** | N/A |

## Context

Wazuh agents authenticate either with a static password or a certificate. We chose certificates as the long-term credential, which meant we had to define a secure means for the certificates to reach the agents, and the access controls around that distribution.

## Decision

Agents authenticate through an industry-standard OIDC / OAuth2 identity provider (Keycloak) using either the interactive authorization-code flow (users) or the client-credentials flow (service accounts). The server validates the resulting JWT (signature, audience, expiry) against the provider's JWKS before issuing a certificate.

## Consequences

- No long-lived static per-agent secrets.
- Identity is delegated to Keycloak; a compromised IdP or JWKS means unauthorized enrollment.
- The certificate's subject is bound to the token's `sub` claim, tying each certificate to a specific identity.

## Rollback

Nothing to roll back.
