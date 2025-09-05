#!/usr/bin/env bash
set -euo pipefail

# Atomic CRL updater: downloads CRL and atomically replaces destination, then reloads service
#
# Required env vars:
# - CRL_URL: HTTP(S) URL to fetch, e.g. https://pki.example.com/crl/issuing.crl
# - DEST_PATH: local path to write CRL, e.g. /etc/nginx/ssl/issuing.crl
# Optional env vars:
# - RELOAD_CMD: command to reload TLS terminator (e.g., "nginx -s reload" or "systemctl reload haproxy")

if [[ -z "${CRL_URL:-}" || -z "${DEST_PATH:-}" ]]; then
  echo "CRL_URL and DEST_PATH are required" >&2
  exit 1
fi

tmp="${DEST_PATH}.tmp.$$"

curl -fsSL -o "$tmp" "$CRL_URL"
chmod 0644 "$tmp"
mv -f "$tmp" "$DEST_PATH"

if [[ -n "${RELOAD_CMD:-}" ]]; then
  echo "Reloading: $RELOAD_CMD"
  bash -c "$RELOAD_CMD"
fi

echo "CRL updated at $DEST_PATH from $CRL_URL"

