# Wazuh Certificate OAuth2

A Rust workspace that brings **certificate-based agent authentication** to **Wazuh**, backed by **OAuth2 / OpenID Connect (OIDC)** identity providers such as **Keycloak**.

This project bridges **identity**, **device trust**, and **certificate lifecycle management** in a clean, auditable way.

> Each crate has its own detailed README. This page provides a high-level overview of the architecture and flow.

---

## What is this?

**Wazuh Certificate OAuth2** enables secure agent enrollment and access control using:

* **Short-lived OAuth2/OIDC tokens** for identity verification
* **mTLS client certificates** for long-term agent authentication
* **Automated revocation** driven by identity provider events

It is designed for **Zero Trust**, **enterprise SOC**, and **cloud-native** environments.

---
## Architecture Overview

The system separates identity verification, certificate issuance,
and cert runtime trust. OAuth2/OIDC is used only for enrollment,
while mTLS is used for all runtime communication.

### Logical Architecture

```text
┌──────────────────────────┐
│   Identity Provider      │
│   (OIDC / OAuth2)        │
│   e.g. Keycloak          │
└─────────────┬────────────┘
              │
              │ OAuth2 Access Token
              ▼
┌──────────────────────────┐
│ wazuh-cert-oauth2-client │
│ (CLI / bootstrap)        │
│──────────────────────────│
│ - Local key generation   │
│ - CSR creation           │
│ - Token-bound request    │
└─────────────┬────────────┘
              │
              │ CSR + Access Token
              ▼
┌──────────────────────────┐
│ wazuh-cert-oauth2-server │
│──────────────────────────│
│ - OIDC token validation  │
│ - Certificate signing   │
│ - Ledger & CRL           │
│ - Protected APIs         │
└─────────────┬────────────┘
              │
              │ mTLS
              ▼
┌──────────────────────────┐
│      Wazuh Manager       │
│──────────────────────────│
│ - Agent auth via certs   │
│ - No shared secrets      │
└──────────────────────────┘

(IdP events: user disabled / group removed)
              │
              ▼
┌──────────────────────────┐
│ wazuh-cert-oauth2-webhook│
│──────────────────────────│
│ - Receives IdP events    │
│ - Triggers revocation    │
│ - Updates CRL            │
└──────────────────────────┘

---

## Core Components

### Server

**`wazuh-cert-oauth2-server`**

* Issues client certificates after successful OIDC authentication
* Manages certificate ledger and CRL
* Protects all APIs using OAuth2/OIDC
* Acts as the trust anchor between IdP and Wazuh agents

See: `crates/wazuh-cert-oauth2-server/README.md`

---

### Client CLI

**`wazuh-cert-oauth2-client`**

* Authenticates via OAuth2/OIDC
* Generates private key + CSR locally
* Registers the agent and retrieves signed certificates
* Designed for automation and headless environments

See: `crates/wazuh-cert-oauth2-client/README.md`

---

### Webhook

**`wazuh-cert-oauth2-webhook`**

* Consumes identity provider events (e.g. user disabled, group removed)
* Triggers certificate revocation requests
* Keeps agent access in sync with IdP state

See: `crates/wazuh-cert-oauth2-webhook/README.md`

---

### Shared Libraries

**`wazuh-cert-oauth2-model`**

* Shared data models
* Telemetry and observability helpers
* Common validation logic

See: `crates/wazuh-cert-oauth2-model/README.md`

---

### Internal Utilities

* `wazuh-cert-oauth2-metrics` – metrics and observability helpers
* `wazuh-cert-oauth2-healthcheck` – readiness / liveness probes

---

## Typical Flow (High Level)

1. **Agent / user authenticates** via OAuth2/OIDC (e.g. Keycloak)
2. **Client CLI receives an access token**
3. **Client generates key + CSR locally**
4. **Server validates token and signs certificate**
5. **Agent uses mTLS** to communicate securely with Wazuh
6. **IdP event occurs** (user disabled, group removed)
7. **Webhook triggers certificate revocation**
8. **CRL is updated**, access is immediately revoked

---

## Quick Start

### Docker Compose (Demo Stack)

Runs a local demo environment with **Keycloak** and **Jaeger**.

```bash
docker compose up -d --build
```

* Server: [http://localhost:8000](http://localhost:8000)
* Webhook: [http://localhost:8100](http://localhost:8100)

---

### Build From Source

```bash
cargo build --release
```

Example server startup:

```bash
target/release/wazuh-cert-oauth2-server \
  --oauth-issuer <issuer-url> \
  --root-ca-path <root-ca.pem> \
  --root-ca-key-path <root-ca-key.pem>
```

---

## Why This Exists

* Avoids shared registration secrets
* Enables **identity-driven agent trust**
* Supports **instant revocation**
* Works well with **Wazuh, Kubernetes, and cloud environments**
* Designed for **auditable SOC workflows**

---

## License

MIT — see `LICENSE`

