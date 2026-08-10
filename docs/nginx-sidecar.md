---
layout: default
title: Nginx Sidecar
parent: Components
nav_order: 5
---

# Nginx Sidecar image

A separate Docker image for an nginx sidecar that validates agent certificates against a CRL before proxying enrollment traffic to the Wazuh manager's `authd`. It is consumed by the Wazuh Helm chart.

## Building the sidecar image

From the repository root:

```bash
docker build -f .docker/nginx-sidecar/Dockerfile -t nginx-sidecar:local .docker/nginx-sidecar/
```

This produces an image based on `nginx:alpine` with `curl`, `openssl`, and `gettext` (for `envsubst`) installed. Stock `nginx:alpine` does **not** work because it lacks these dependencies.

## How it works

1. `entrypoint.sh` uses `envsubst` to render `nginx.conf.template` → `/etc/nginx/nginx.conf`.
2. Runs an initial CRL fetch via `fetch-crl.sh` (bypasses `If-None-Match` to avoid long-poll delay on startup).
3. Starts a background CRL refresh loop (long-polling with ETag support).
4. Launches nginx in the foreground.

## Environment variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `LISTEN_PORT` | `1515` | Port for agent mTLS connections. |
| `AUTHD_UPSTREAM_HOST` | `127.0.0.1` | Wazuh manager authd host. |
| `AUTHD_UPSTREAM_PORT` | `15151` | Wazuh manager authd port. |
| `SSL_CERT_PATH` | `/etc/ssl/certs/server.pem` | Server certificate (PEM). |
| `SSL_KEY_PATH` | `/etc/ssl/certs/server-key.pem` | Server private key (PEM). |
| `SSL_CA_PATH` | `/etc/ssl/certs/ca.pem` | CA certificate for client verification. |
| `CRL_FILE` | `/etc/nginx/crl/crl.pem` | Path to the CRL file (PEM). |
| `CRL_ENABLED` | `true` | Enable/disable CRL validation. |
| `CRL_URL` | *(required when CRL enabled)* | Cert-server CRL endpoint URL. |
| `CRL_REFRESH_INTERVAL` | `300` | Seconds between CRL refresh retries on error. |
| `CURL_TIMEOUT` | `35` | Curl timeout (must exceed server long-poll timeout). |
| `LOG_LEVEL` | `debug` | nginx error log level. |
| `WORKER_CONNECTIONS` | `1024` | nginx `worker_connections`. |
