---
layout: default
title: Components
nav_order: 3
has_children: true
---

# Components

The `wazuh-cert-oauth2` workspace is made up of the following components, each documented in its own page:

| Component | Crate / Image | Role |
| :--- | :--- | :--- |
| [Server](server) | `wazuh-cert-oauth2-server` | Validates OIDC tokens, signs CSRs with a Root CA, maintains the ledger and CRL. |
| [Client](client) | `wazuh-cert-oauth2-client` | CLI on the agent host: authenticates via OIDC, generates key + CSR, registers the agent. |
| [Webhook](webhook) | `wazuh-cert-oauth2-webhook` | Consumes IdP events, triggers revocations, and evicts Wazuh agents. |
| [Model](model) | `wazuh-cert-oauth2-model` | Shared types, services, and helpers. |
| [Nginx Sidecar](nginx-sidecar) | `nginx-sidecar` image | CRL-validating reverse proxy for agent enrollment traffic. |

There is also an internal utility crate, `wazuh-cert-oauth2-healthcheck`.
