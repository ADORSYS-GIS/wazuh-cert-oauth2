---
layout: default
title: Webhook
parent: Components
nav_order: 3
---

# Webhook Proxy (`wazuh-cert-oauth2-webhook`)

A specialized service that listens for events from the Identity Provider (e.g. Keycloak). It features persistent disk-backed spooling for reliable delivery of revocations, GitHub issue creation, and Wazuh agent evictions via the Wazuh Manager REST API.

## Purpose

- Receives webhooks from the OIDC/IdP (e.g. Keycloak) and translates them into certificate revocations.
- Forwards revocation requests to the server with retry and persistent spooling.
- Evicts Wazuh agents via the Wazuh Manager REST API when certificates are revoked.
- Supports multiple inbound auth options for the webhook endpoint (Basic, Bearer, API key, or anonymous when none configured).
- Can acquire an OAuth2 client-credentials token (or use a static bearer) to call the server.

## Endpoints

| Method | Path | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Liveness probe. |
| `POST` | `/api/webhook` | Receives IdP event payloads; will ignore, revoke, or create a GitHub ticket depending on event type. |
| `POST` | `/api/internal/evict` | Internal endpoint for the cert server to trigger agent eviction after auto-rotate override. |

## Eviction pipeline

When a certificate is revoked, the webhook evicts the corresponding Wazuh agent:

1. **Keycloak-triggered** (user-delete/user-update): The webhook fetches the agent name from the ledger, revokes the cert, then queues an `EvictRequest`. For `user-update` events, the representation is parsed and revocation only happens when `enabled: false` (user disabled); `enabled: true` is ignored. Missing/unparseable representation fails safe to revocation. The spool processor resolves the agent by name via the Wazuh API (exact match using `q=name=`). For non-auto-rotate evictions a grace deadline is set; the item is re-written atomically to disk and skipped until the deadline elapses.
2. **Auto-rotate** (server-triggered): The cert-server calls `/api/internal/evict` when a re-enrollment overrides an active cert. The grace period is skipped and the old agent is deleted immediately.

If the Wazuh API is unreachable, the `EvictRequest` is persisted to the spool directory and retried with exponential backoff. Eviction spool items older than the TTL are dead-lettered to prevent unbounded retry of poison messages. If both the direct eviction call and the spool queue reject the request, the endpoint returns `500`.

See [Agent eviction](../features-eviction) for the full feature walkthrough, including grace periods, auto-rotate, and resilience.

## Configuration

| Flag | Env Variable | Default | Purpose |
| :--- | :--- | :--- | :--- |
| `--server-base-url` | `SERVER_BASE_URL` | (required) | Base URL of the server. |
| `--database-url` | `DATABASE_URL` | (optional) | PostgreSQL DSN. When set, the spool uses PostgreSQL (multi-replica safe); otherwise it falls back to the on-disk JSON spool directory at `SPOOL_DIR`. |
| `--spool-dir` | `SPOOL_DIR` | `/data/spool` | Directory for queued revoke requests (local-dev fallback). |
| `--retry-attempts` | `RETRY_ATTEMPTS` | `5` | Max retry attempts per revoke. |
| `--retry-base-ms` | `RETRY_BASE_MS` | `500` | Initial backoff. |
| `--retry-max-ms` | `RETRY_MAX_MS` | `8000` | Maximum backoff. |
| `--spool-interval-secs` | `SPOOL_INTERVAL_SECS` | `10` | Interval between spool scans. |
| `--proxy-bearer-token` | `PROXY_BEARER_TOKEN` | (none) | Static bearer token for calls to the server (mutually exclusive with OAuth2). |
| `--oauth-issuer` | `OAUTH_ISSUER` | (optional) | OIDC issuer for discovery. |
| `--oauth-client-id` | `OAUTH_CLIENT_ID` | (none) | OAuth client id. |
| `--oauth-client-secret` | `OAUTH_CLIENT_SECRET` | (none) | OAuth client secret. |
| `--oauth-scope` | `OAUTH_SCOPE` | (optional) | Optional scope. |
| `--oauth-audience` | `OAUTH_AUDIENCE` | (optional) | Optional audience. |
| `--keycloak-revoke-reason` | `KEYCLOAK_REVOKE_REASON` | `Keycloak event` | Reason attached to server revoke requests. |
| `--github-token` | `GITHUB_TOKEN` | (optional) | GitHub PAT for issue creation. |
| `--github-repo-owner` | `GITHUB_REPO_OWNER` | (optional) | Owner of the repo for tickets. |
| `--github-repo-name` | `GITHUB_REPO_NAME` | (optional) | Name of the repo for tickets. |
| `--keycloak-admin-base-url` | `KEYCLOAK_ADMIN_BASE_URL` | (optional) | Base URL for the Keycloak Admin API. |
| `--wazuh-manager-url` | `WAZUH_MANAGER_URL` | (optional) | Wazuh Manager API URL. |
| `--wazuh-api-user` | `WAZUH_API_USER` | (optional) | Wazuh API user. |
| `--wazuh-api-password` | `WAZUH_API_PASSWORD` | (optional) | Wazuh API password. |
| `--wazuh-api-token` | `WAZUH_API_TOKEN` | (optional) | Wazuh API static token. |
| `--wazuh-eviction-grace-seconds` | `WAZUH_EVICTION_GRACE_SECONDS` | `30` | Grace period before agent deletion (skipped for auto-rotate). |
| `--wazuh-api-tls-verify` | `WAZUH_API_TLS_VERIFY` | `true` | Enable TLS verification for the Wazuh Manager API. |
| `--wazuh-api-ca-bundle` | `WAZUH_API_CA_BUNDLE` | (optional) | PEM CA bundle for the Wazuh Manager API. |

### Inbound webhook auth

Any set option is accepted:

| Flag | Env Variable |
| :--- | :--- |
| `--webhook-basic-user` | `WEBHOOK_BASIC_USER` |
| `--webhook-basic-password` | `WEBHOOK_BASIC_PASSWORD` |
| `--webhook-api-key` | `WEBHOOK_API_KEY` |
| `--webhook-bearer-token` | `WEBHOOK_BEARER_TOKEN` |

## Data and persistence

The spool backend is configurable:

- **PostgreSQL (recommended for multi-replica):** set `DATABASE_URL`. The webhook
  stores spool items in the shared `spool_item` table and claims them with
  `SELECT ... FOR UPDATE SKIP LOCKED`, so multiple webhook replicas can run
  safely without double-processing. Dead-lettering is in-table
  (`state = 'dead_letter'`).
- **Directory (local-dev / fallback):** when `DATABASE_URL` is unset, the webhook
  uses the on-disk JSON spool directory at `SPOOL_DIR`, with a dead-letter
  directory for expired eviction items.

Mount a writable volume at `/data` (or adjust `--spool-dir`) for durable spooling
when using the directory fallback.

```bash
wazuh-cert-oauth2-webhook --help
```
