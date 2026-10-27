---
layout: default
title: Home
nav_order: 1
description: Wazuh Certificate OAuth2 documentation
---

# Wazuh Certificate OAuth2

> **Certificate-based agent authentication for Wazuh**, backed by **OAuth2 / OpenID
> Connect (OIDC)** identity providers such as **Keycloak**.

This project bridges **identity**, **device trust**, and **certificate lifecycle
management** in a clean, auditable way. It enables secure agent enrollment and
access control using short-lived OIDC tokens, mTLS client certificates, and
automated revocation driven by identity-provider events.

## Components

| Component | Role |
| :--- | :--- |
| [Server](docs/architecture/server) | Validates OIDC tokens, signs CSRs with a Root CA, maintains the issuance ledger and CRL. |
| [Client](docs/architecture/client) | CLI on the agent host: authenticates via OIDC, generates a key + CSR, and registers the agent. |
| [Webhook](docs/architecture/webhook) | Consumes IdP events (e.g. Keycloak), triggers revocations, and evicts Wazuh agents automatically. |
| [Model](docs/architecture/model) | Shared types, services, and helpers reused across the workspace. |
| [Nginx Sidecar](docs/architecture/nginx-sidecar) | CRL-validating reverse proxy for agent enrollment traffic. |

## Quick links

- [Features](docs/reference/features): what the project does end-to-end.
- [Components](docs/architecture/components): the server, client, webhook, model, and nginx sidecar.
- [Architecture](docs/architecture/architecture): component overview and communication flows.
- [Getting Started](docs/operations/getting-started): run the stack with Docker Compose or from source.
- Source code: [ADORSYS-GIS/wazuh-cert-oauth2](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2)
