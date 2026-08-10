---
layout: default
title: Certificate issuance & lifecycle
parent: Features
nav_order: 2
---

# Certificate issuance & lifecycle

The server signs CSRs to a **Root CA** and manages the full lifecycle of each certificate: issuance, ledger tracking, revocation, and CRL publication.

## Issuance flow

1. The client generates a fresh keypair and a CSR whose subject is derived from the token's `sub` claim.
2. The client submits the CSR to `POST /api/register-agent` with a Bearer token.
3. The server validates the token, then signs the CSR using the configured Root CA (`--root-ca-path` / `--root-ca-key-path`).
4. The signed certificate, CA certificate, and private key are returned and saved to the agent host.

## Certificate contents

- **Subject CN**: the JWT subject (`sub`).
- **SANs**:
  - a DNS entry mirroring the CN for compatibility;
  - an identity URI binding the issuer realm and subject: `{iss}#sub={sub}`.
- **Key usage**: digital signature (plus key encipherment for RSA).
- **EKU**: `clientAuth` (client authentication only).
- **CDP**: optional CRL distribution point URL (`--crl-dist-url`) embedded in issued certs.

## Issuance ledger

Every issue and revoke is recorded to a durable **CSV ledger** (`--ledger-path`) with columns:

`subject, serial_hex, issued_at_unix, revoked, revoked_at_unix, reason, issuer, realm, wazuh_agent_name`

The ledger makes it possible to look up an agent by subject or serial for fast ban/revocation decisions, and it feeds agent eviction (agent name is recorded at enrollment).

## Revocation & CRL

- Revocations can be triggered by serial or subject (`POST /api/revoke`) or automatically from identity-provider events.
- On revoke, the server marks the ledger entry, **rebuilds the CRL**, and writes it to `--crl-path`.
- The CRL is served at `GET /crl/issuing.crl` and consumed by the nginx sidecar for live validation.

## Auto-rotate / single-cert policy

When an agent re-enrolls with `overwrite` set, the server detects any **active certificate for the same subject**, revokes the old one, and rebuilds the CRL. This enforces one live certificate per subject and notifies the webhook to evict the stale agent immediately.
