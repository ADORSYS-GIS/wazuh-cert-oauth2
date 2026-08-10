---
layout: default
title: Features
nav_order: 2
has_children: true
---

# Features

`wazuh-cert-oauth2` secures agent enrollment and access control for Wazuh using a modern identity + certificate lifecycle. Each feature is documented in its own page.

## Identity & access

- **OIDC / OAuth2 agent authentication**: agents authenticate through any industry-standard identity provider (e.g. Keycloak) using authorization and client-credentials flows. See [Authentication](../features-auth).
- **JWT validation**: the server discovers the OIDC issuer, fetches JWKS, and validates token signature, audience, and expiry.

## Certificate lifecycle

- **Automatic CSR signing**: the client generates a key + CSR; the server signs it to a **Root CA**. See [Certificate issuance & lifecycle](../features-certificates).
- **Issuance ledger**: every issue/revoke is recorded to a durable CSV ledger for audit and fast revocation lookups.
- **CRL management**: revoked certificates are published on a Certificate Revocation List served by the server.
- **Auto-rotate / single-cert policy**: re-enrollment overrides and revokes an active certificate for the same subject.

## Trust lifecycle automation

- **Event-driven revocation**: the Webhook Proxy consumes identity-provider events and revokes the matching certificates automatically. See [Automated revocation](../features-revocation).
- **Wazuh agent eviction**: revoked agents are resolved and removed from the Wazuh Manager, with configurable grace periods. See [Agent eviction](../features-eviction).
- **Reliable delivery**: disk-backed spooling with retry/backoff and dead-letter handling guarantees revocations survive outages. See [Reliability & spooling](../features-reliability).
- **GitHub integration**: new user registrations automatically open a tracking issue. See [GitHub issue tracking](../features-github).

## Deployment & infrastructure

- **Nginx CRL sidecar**: a reverse proxy validates agent certificates against the live CRL before proxying to `authd`. See [Nginx CRL sidecar](../features-sidecar).
- **Helm chart**: packaged for Kubernetes-based deployments.
- **Zero-trust posture**: short-lived identities, per-subject certificates, auditable revocation, and no shared per-agent secrets.

## Where to go next

| Topic | Page |
| :--- | :--- |
| What the software does | [Features — this page](.) |
| Each component's role | [Components](../components) |
| How the pieces interact | [Architecture](../architecture) |
| Wire it up yourself | [Getting Started](../getting-started) |
