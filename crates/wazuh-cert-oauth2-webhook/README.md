# Wazuh Certificate OAuth2 Webhook

Purpose

- Receives webhooks from the OIDC/IdP (e.g., Keycloak) and translates them into certificate revocations.
- Forwards revocation requests to the server with retry and persistent spooling.
- Evicts Wazuh agents via the Wazuh Manager REST API when certificates are revoked.
- Supports multiple inbound auth options for the webhook endpoint (Basic, Bearer, API key, or anonymous when none configured).
- Can acquire an OAuth2 client-credentials token (or use a static bearer) to call the server.

Endpoints

- `GET /health`: liveness probe.
- `POST /api/webhook`: receives IdP event payloads; will ignore, revoke, or create a GitHub ticket depending on event type.
- `POST /api/internal/evict`: internal endpoint for the cert server to trigger agent eviction after auto-rotate override.

Eviction Pipeline

When a certificate is revoked, the webhook evicts the corresponding Wazuh agent:

1. **Keycloak-triggered** (user-delete/user-update): The webhook fetches the agent name from the ledger, revokes the cert, then queues an `EvictRequest`. For `user-update` events, the webhook representation is parsed and revocation is only triggered when `enabled: false` (user being disabled); `enabled: true` (user re-enabled) is ignored. Missing/unparseable representation fails safe to revocation. The spool processor resolves the agent by name via the Wazuh API (exact match using `q=name=`). For non-auto-rotate evictions, the processor sets a grace deadline (`delete_after_unix`) and re-writes the spool file atomically (temp-file + rename) instead of blocking: the item is skipped until the deadline elapses, allowing other spool items to be processed concurrently. Once due, the agent is deleted via the Wazuh API.

2. **Auto-rotate** (server-triggered): The cert-server calls `/api/internal/evict` when a re-enrollment overrides an active cert. The grace period is skipped. The old agent is deleted immediately.

If the Wazuh API is unreachable, the `EvictRequest` is persisted to the spool directory and retried with exponential backoff. Eviction spool items older than 24 hours are force-deleted (dead-lettered) to prevent unbounded retry of poison messages. If both the direct eviction call and the spool queue reject the request, the endpoint returns `500 Internal Server Error`.

Configuration

- `--server-base-url` (`SERVER_BASE_URL`): Base URL of the server (required), e.g. `https://cert.wazuh.example`.
- `--spool-dir` (`SPOOL_DIR`, default `/data/spool`): Directory for queued revoke requests.
- `--retry-attempts` (`RETRY_ATTEMPTS`, default 5): Max retry attempts per revoke.
- `--retry-base-ms` (`RETRY_BASE_MS`, default 500): Initial backoff.
- `--retry-max-ms` (`RETRY_MAX_MS`, default 8000): Maximum backoff.
- `--spool-interval-secs` (`SPOOL_INTERVAL_SECS`, default 10): Interval between spool scans.
- `--proxy-bearer-token` (`PROXY_BEARER_TOKEN`): Static bearer token for calls to the server (mutually exclusive with OAuth2).
- `--oauth-issuer` (`OAUTH_ISSUER`): OIDC issuer for discovery (optional; used to get tokens for server).
- `--oauth-client-id` (`OAUTH_CLIENT_ID`): OAuth client id.
- `--oauth-client-secret` (`OAUTH_CLIENT_SECRET`): OAuth client secret.
- `--oauth-scope` (`OAUTH_SCOPE`): Optional scope.
- `--oauth-audience` (`OAUTH_AUDIENCE`): Optional audience.
- `--keycloak-revoke-reason` (`KEYCLOAK_REVOKE_REASON`, default `Keycloak event`): Reason string attached to server revoke requests.
- `--github-token` (`GITHUB_TOKEN`): GitHub PAT for issue creation (optional).
- `--github-repo-owner` (`GITHUB_REPO_OWNER`): Owner of the repo for tickets (optional).
- `--github-repo-name` (`GITHUB_REPO_NAME`): Name of the repo for tickets (optional).
- `--keycloak-admin-base-url` (`KEYCLOAK_ADMIN_BASE_URL`): Base URL for Keycloak Admin API (optional).
- `--wazuh-manager-url` (`WAZUH_MANAGER_URL`): Wazuh Manager API URL (optional, for eviction).
- `--wazuh-api-user` (`WAZUH_API_USER`): Wazuh API user (optional).
- `--wazuh-api-password` (`WAZUH_API_PASSWORD`): Wazuh API password (optional).
- `--wazuh-api-token` (`WAZUH_API_TOKEN`): Wazuh API static token (optional).
- `--wazuh-eviction-grace-seconds` (`WAZUH_EVICTION_GRACE_SECONDS`, default 30): Grace period before agent deletion (skipped for auto-rotate).
- `--wazuh-api-tls-verify` (`WAZUH_API_TLS_VERIFY`, default true): Enable TLS certificate verification for the Wazuh Manager API. Set to `false` only for testing or self-signed certificates without a configured CA bundle.
- `--wazuh-api-ca-bundle` (`WAZUH_API_CA_BUNDLE`): Path to a PEM file containing additional CA certificates to trust for the Wazuh Manager API (e.g. for self-signed managers).
- Inbound webhook auth (any set are accepted):
  - `--webhook-basic-user` (`WEBHOOK_BASIC_USER`)
  - `--webhook-basic-password` (`WEBHOOK_BASIC_PASSWORD`)
  - `--webhook-api-key` (`WEBHOOK_API_KEY`)
  - `--webhook-bearer-token` (`WEBHOOK_BEARER_TOKEN`)

Data and persistence

- Mount a writable volume at `/data` (or adjust `--spool-dir`) for durable spooling.

Logging

- `tracing_subscriber` is initialized automatically; logs are emitted to stdout.
- Control verbosity with `RUST_LOG` (e.g., `info,rocket=warn,reqwest=warn`). Defaults to `info` if unset.

## Quick start

For detailed setup and run instructions, see the [Getting Started Guide](../../docs/getting-started.md).

```bash
# General usage
wazuh-cert-oauth2-webhook --help
```

