---
layout: default
title: Agent eviction
parent: Features
nav_order: 4
---

# Agent eviction

When a certificate is revoked, the corresponding Wazuh agent is removed from the manager automatically. The Webhook Proxy resolves the agent by name via the **Wazuh Manager REST API** and deletes it.

## Keycloak-triggered eviction

1. Keycloak fires a user-delete or user-update (disabled) event.
2. The webhook fetches the agent name from the ledger (`GET /api/ledger/subject/{subject}`).
3. It revokes the certificate, then queues an `EvictRequest`.
4. The spool processor resolves the agent via `GET /agents?q=name={agent_name}` (exact match) and deletes it with `DELETE /agents/{id}`.

## Auto-rotate eviction (server-triggered)

When the server detects a re-enrollment that overrides an active certificate, it calls `POST /api/internal/evict`. For these evictions the **grace period is skipped** and the old agent is deleted immediately.

## Grace period

For Keycloak-triggered revocations, the spool processor sets a grace deadline (`delete_after_unix`, default `WAZUH_EVICTION_GRACE_SECONDS` = 30s) and re-writes the spool item atomically instead of blocking. The item is skipped until the deadline elapses, allowing other spool items to be processed concurrently. Auto-rotate evictions bypass the grace period entirely.

## Resilience & safety

- **Unreachable manager**: if the Wazuh API is unreachable, the `EvictRequest` stays in the spool and is retried with exponential backoff; rewrites are atomic (temp-file + rename) to avoid corruption on crash.
- **TTL dead-letter**: eviction items older than the TTL (`SPOOL_EVICT_TTL_SECS`, default 24h) are moved to the dead-letter directory instead of retried forever. See [Reliability & spooling](../features-reliability).
- **Double-failure safety**: if both the direct eviction call and the spool queue fail, `/api/internal/evict` returns `500`, so the caller knows the request was lost and can retry.

## Wazuh API configuration

The proxy talks to the manager using `--wazuh-manager-url` plus user/password or a static token. TLS verification defaults to `true` (`--wazuh-api-tls-verify`) and can point at a custom CA bundle (`--wazuh-api-ca-bundle`) for self-signed managers.
