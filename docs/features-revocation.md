---
layout: default
title: Automated revocation
parent: Features
nav_order: 3
---

# Automated revocation

The **Webhook Proxy** turns identity-provider events into certificate revocations automatically, when a user is deleted or disabled, their certificates are revoked without operator intervention.

## Event handling

- The proxy receives events at `POST /api/webhook` from the IdP (e.g. Keycloak).
- **`USER-DELETE`**: always triggers revocation.
- **`USER-UPDATE`**: the user representation is parsed; revocation is triggered only when `enabled: false` (user being disabled). If the user is being re-enabled (`enabled: true`) the event is ignored. If the representation is missing or unparseable, the proxy **fails safe to revocation**.

## Forwarding revocations

- The proxy calls `POST /api/revoke` on the server with the subject (userId), attaching a configurable reason (`--keycloak-revoke-reason`, default `Keycloak event`).
- It authenticates to the server either with a static bearer (`--proxy-bearer-token`) or an **OAuth2 client-credentials** token (`--oauth-*`).

## Multiple inbound auth modes

The webhook endpoint itself can be protected by any (or none) of:

| Auth mode | Flags |
| :--- | :--- |
| Basic | `--webhook-basic-user` / `--webhook-basic-password` |
| Bearer | `--webhook-bearer-token` |
| API key | `--webhook-api-key` |
| Anonymous | when none are configured |

## Resiliency

If the server is down or the request fails, the revocation request is persisted to the spool directory and retried with **exponential backoff** (`--retry-*`), so revocations are eventually delivered even during outages.

Related: [Reliability & spooling](../features-reliability), [Agent eviction](../features-eviction).
