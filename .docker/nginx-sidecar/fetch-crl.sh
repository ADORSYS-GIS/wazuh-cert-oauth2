#!/bin/sh
set -e

# Configurable via environment (defaults provided by entrypoint.sh or Helm chart)
CRL_URL="${CRL_URL:?CRL_URL is required}"
CRL_FILE="${CRL_FILE:-/etc/nginx/crl/crl.pem}"
TEMP_FILE="${CRL_FILE}.tmp"
ETAG_FILE="${CRL_FILE}.etag"
# Fixed watchdog path — the Helm chart's liveness probe checks this exact path
WATCHDOG_FILE="/etc/nginx/crl/.last_refresh"
CURL_TIMEOUT="${CURL_TIMEOUT:-35}"

# Read last-known ETag if available
LAST_ETAG=""
if [ -f "${ETAG_FILE}" ]; then
    LAST_ETAG=$(cat "${ETAG_FILE}")
fi

echo "Fetching CRL from ${CRL_URL}..."
if [ -n "${LAST_ETAG}" ]; then
    echo "Using ETag: ${LAST_ETAG}"
fi

# Fetch CRL with long-polling support
# If server supports it, this will block up to the server's long-poll timeout
# waiting for changes. CURL_TIMEOUT must be greater than the server
# long-poll timeout (default 25s) to allow the full hold.
HTTP_CODE=$(curl -fsSL --max-time "${CURL_TIMEOUT}" \
    -w "%{http_code}" \
    -o "${TEMP_FILE}" \
    -D "${TEMP_FILE}.headers" \
    ${LAST_ETAG:+-H "If-None-Match: \"${LAST_ETAG}\""} \
    "${CRL_URL}" 2>/dev/null || echo "000")

if [ "${HTTP_CODE}" = "304" ]; then
    echo "CRL unchanged (304), no update needed"
    rm -f "${TEMP_FILE}" "${TEMP_FILE}.headers"
    # Touch watchdog even on 304 — the refresh loop is alive and CRL is current
    date +%s > "${WATCHDOG_FILE}"
    exit 2
fi

if [ "${HTTP_CODE}" = "000" ]; then
    echo "Failed to connect to CRL server"
    rm -f "${TEMP_FILE}" "${TEMP_FILE}.headers"
    exit 1
fi

if [ "${HTTP_CODE}" -lt 200 ] || [ "${HTTP_CODE}" -ge 300 ]; then
    echo "Failed to fetch CRL (HTTP ${HTTP_CODE})"
    rm -f "${TEMP_FILE}" "${TEMP_FILE}.headers"
    exit 1
fi

# Extract new ETag from response headers
NEW_ETAG=$(grep -i '^ETag:' "${TEMP_FILE}.headers" 2>/dev/null | sed 's/^ETag: *//i; s/"//g; s/^[Ww]\/ *//' | tr -d '\r\n')
if [ -n "${NEW_ETAG}" ]; then
    echo "${NEW_ETAG}" > "${ETAG_FILE}"
    echo "New ETag saved: ${NEW_ETAG}"
fi
rm -f "${TEMP_FILE}.headers"

# Convert DER to PEM if needed (ALWAYS write to a temp file first, then
# atomically mv to CRL_FILE to avoid nginx reading a half-written CRL).
if head -1 "${TEMP_FILE}" | grep -q "BEGIN X509 CRL"; then
    mv "${TEMP_FILE}" "${CRL_FILE}"
else
    if ! openssl crl -in "${TEMP_FILE}" -inform DER -out "${TEMP_FILE}.pem" -outform PEM 2>/dev/null; then
        echo "ERROR: Failed to convert CRL from DER to PEM"
        rm -f "${TEMP_FILE}"
        exit 1
    fi
    mv "${TEMP_FILE}.pem" "${CRL_FILE}"
    rm -f "${TEMP_FILE}"
fi

echo "CRL updated successfully (HTTP ${HTTP_CODE})"

# Update watchdog timestamp
date +%s > "${WATCHDOG_FILE}"

# Restore ssl_crl from backup if it was previously removed
if [ -f /etc/nginx/nginx.conf.with_crl ] && ! grep -q 'ssl_crl' /etc/nginx/nginx.conf; then
    echo "Restoring ssl_crl from backup..."
    cp /etc/nginx/nginx.conf.with_crl /etc/nginx/nginx.conf
    nginx -t && echo "CRL config restored successfully"
fi

# Reload nginx to pick up new CRL
if ! nginx -s reload 2>&1; then
    echo "Nginx reload failed (expected on initial startup before nginx starts)"
fi
