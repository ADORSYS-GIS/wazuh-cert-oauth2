---
layout: default
title: Nginx CRL sidecar
parent: Features
nav_order: 7
---

# Nginx CRL sidecar

A dedicated reverse proxy that validates agent certificates against the live **Certificate Revocation List (CRL)** **before** proxying enrollment traffic to the Wazuh manager's `authd`. It is consumed by the Wazuh Helm chart.

## Why it's needed

Stock `nginx:alpine` can't do this out of the box, the sidecar image adds `curl`, `openssl`, and `gettext` (for `envsubst`) so it can fetch and validate a CRL.

## Runtime behavior

1. `entrypoint.sh` uses `envsubst` to render `nginx.conf.template` → `/etc/nginx/nginx.conf`.
2. Runs an **initial CRL fetch** via `fetch-crl.sh` (bypassing `If-None-Match` to avoid the long-poll delay on startup).
3. Starts a **background CRL refresh loop** that long-polls the cert server's CRL endpoint with ETag support.
4. Launches nginx in the foreground.

Because the CRL is validated at the edge, revoked certificates are rejected on enrollment even if the manager hasn't removed them yet.

## Key configuration

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `CRL_ENABLED` | `true` | Enable/disable CRL validation. |
| `CRL_URL` | *(required when enabled)* | Cert-server CRL endpoint URL. |
| `CRL_REFRESH_INTERVAL` | `300` | Seconds between CRL refresh retries on error. |
| `CURL_TIMEOUT` | `35` | Must exceed the server's long-poll timeout. |
| `SSL_CERT_PATH` / `SSL_KEY_PATH` / `SSL_CA_PATH` | `/etc/ssl/certs/...` | Server credentials and CA for client verification. |
| `LISTEN_PORT` | `1515` | Port for agent mTLS connections. |
| `AUTHD_UPSTREAM_HOST` / `PORT` | `127.0.0.1` / `15151` | Wazuh manager `authd` upstream. |

See the [Nginx sidecar component page](../components/nginx-sidecar) for the full variable reference.
