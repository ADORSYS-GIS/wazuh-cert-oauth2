---
layout: default
title: Features
nav_order: 2
---

# Features

`wazuh-cert-oauth2` secures agent enrollment and access control for Wazuh using a modern identity + certificate lifecycle. Here's what it does end-to-end.

## Identity & access

- **OIDC / OAuth2 agent authentication** — agents authenticate through any industry-standard identity provider (e.g. Keycloak) using RFC 8252–style authorization and client-credentials flows, instead of static shared credentials.
- **Short-lived token + long-lived mTLS** — a one-time OIDC token proves identity at enrollment; a signed **mTLS client certificate** provides the long-term, revocable credential the Wazuh agent uses afterward.
- **JWT validation** — the server discovers the OIDC issuer, fetches JWKS, and validates token signature, audience, and expiry.

## Certificate lifecycle

- **Automatic CSR signing** — the client generates a key + CSR; the server signs it to a **Root CA**, binding the identity to the certificate via subject CN, DNS SAN, and an identity URI SAN (`{iss}#sub={sub}`).
- **Issuance ledger** — every issue/revoke is recorded to a durable CSV ledger for audit and fast ban/revocation lookups by subject or serial.
- **CRL management** — revoked certificates are published on a Certificate Revocation List served by the server.
- **Auto-rotate / single-cert policy** — re-enrollment overrides and revokes an active certificate for the same subject.

## Trust lifecycle automation

- **Event-driven revocation** — the **Webhook Proxy** consumes identity-provider events (user deleted / disabled) and revokes the matching certificates automatically, failing safe on unparseable payloads.
- **Wazuh agent eviction** — when a certificate is revoked, the matching agent is resolved by name and removed from the Wazuh Manager REST API. Includes a configurable grace period, and skips it entirely for auto-rotate evictions.
- **Reliable delivery** — disk-backed **spooling** with exponential retry/backoff guarantees revocation and eviction survive server outages; stale items are moved to a **dead-letter** directory (never lost, always replayable).
- **GitHub integration** — new user registrations can automatically open a tracking issue in a configured repository.

## Deployment & infrastructure

- **Nginx CRL sidecar** — a dedicated reverse proxy validates agent certificates against the live CRL **before** proxying enrollment traffic to the Wazuh manager's `authd`, with background ETag long-polling CRL refresh.
- **Helm chart** — packaged as a Helm chart for Kubernetes-based deployments.
- **Multiple inbound auth modes** — the webhook accepts Basic, Bearer, API key, or (when none configured) anonymous traffic.
- **Zero-trust posture** — short-lived identities, per-subject certificates, auditable revocation, and no shared per-agent secrets.

## Where to go next

| Topic | Page |
| :--- | :--- |
| What each component does | [Components](components) |
| How the pieces interact | [Architecture](architecture) |
| Wire it up yourself | [Getting Started](getting-started) |
| What's coming next | [Roadmap](roadmap) |
