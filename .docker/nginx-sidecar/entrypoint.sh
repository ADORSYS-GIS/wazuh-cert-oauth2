#!/bin/sh
set -e

# Defaults (can be overridden via environment variables)
LOG_LEVEL="${LOG_LEVEL:-debug}"
WORKER_CONNECTIONS="${WORKER_CONNECTIONS:-1024}"
LISTEN_PORT="${LISTEN_PORT:-1515}"
AUTHD_UPSTREAM_HOST="${AUTHD_UPSTREAM_HOST:-127.0.0.1}"
AUTHD_UPSTREAM_PORT="${AUTHD_UPSTREAM_PORT:-15151}"
SSL_CERT_PATH="${SSL_CERT_PATH:-/etc/ssl/certs/server.pem}"
SSL_KEY_PATH="${SSL_KEY_PATH:-/etc/ssl/certs/server-key.pem}"
SSL_CA_PATH="${SSL_CA_PATH:-/etc/ssl/certs/ca.pem}"
CRL_FILE="${CRL_FILE:-/etc/nginx/crl/crl.pem}"
CRL_ENABLED="${CRL_ENABLED:-true}"

# Create required directories
mkdir -p /etc/nginx/crl /var/log/nginx

# Render nginx config from template using envsubst
# We list ONLY our variables to avoid mangling nginx's own $variable references
# (e.g., $remote_addr, $time_local, etc.)
envsubst '${LOG_LEVEL} ${WORKER_CONNECTIONS} ${LISTEN_PORT} ${AUTHD_UPSTREAM_HOST} ${AUTHD_UPSTREAM_PORT} ${SSL_CERT_PATH} ${SSL_KEY_PATH} ${SSL_CA_PATH} ${CRL_FILE}' \
    < /opt/sidecar/nginx.conf.template \
    > /etc/nginx/nginx.conf
echo "Nginx config rendered from template"

# If CRL is disabled, remove ssl_crl directive so nginx doesn't require the file
if [ "${CRL_ENABLED}" != "true" ]; then
    echo "CRL disabled (CRL_ENABLED=${CRL_ENABLED}), removing ssl_crl from config"
    sed -i '/ssl_crl/d' /etc/nginx/nginx.conf
fi

# Initial CRL fetch (MUST happen before nginx validation since ssl_crl requires the file)
if [ "${CRL_ENABLED}" = "true" ]; then
    echo "Performing initial CRL fetch..."
    rc=0
    /opt/sidecar/fetch-crl.sh || rc=$?
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
        echo "Initial CRL fetch successful"
    else
        echo "WARNING: Initial CRL fetch failed. Removing ssl_crl from nginx config..."
        # Save original config with CRL for later restoration
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.with_crl
        # Remove ssl_crl so nginx can start without a CRL file
        sed -i '/ssl_crl/d' /etc/nginx/nginx.conf
        echo "ssl_crl removed from config"
        # Create empty CRL file so readiness/liveness probes don't fail
        touch "$CRL_FILE"
        # Seed watchdog so liveness probe passes while CRL server is down
        date +%s > /etc/nginx/crl/.last_refresh
    fi
else
    echo "CRL disabled, skipping initial CRL fetch"
    # Create empty CRL file for probes
    touch "$CRL_FILE" 2>/dev/null || true
    date +%s > /etc/nginx/crl/.last_refresh 2>/dev/null || true
fi

# Validate nginx config
if ! nginx -t 2>&1; then
    echo "ERROR: Nginx configuration test failed"
    exit 1
fi
echo "Nginx config validated successfully"

# Start CRL refresh loop in background (only when CRL is enabled)
# Note: set -e is NOT inherited by the subshell, so we handle errors
# explicitly. The watchdog file (.last_refresh) is updated on every
# successful CRL fetch (including 304s). The liveness probe checks
# this file to detect a stuck refresh loop.
if [ "${CRL_ENABLED}" = "true" ]; then
    (
        INTERVAL="${CRL_REFRESH_INTERVAL:-300}"
        echo "Starting CRL refresh loop (interval: ${INTERVAL}s, long-polling enabled)"
        while true; do
            rc=0
            /opt/sidecar/fetch-crl.sh || rc=$?
            if [ "$rc" -eq 2 ]; then
                # 304 Not Modified - long-poll already waited, re-poll immediately
                continue
            elif [ "$rc" -eq 0 ]; then
                # CRL updated - brief pause before next long-poll
                sleep 2
            else
                # Error - back off before retry
                echo "CRL refresh failed (exit ${rc}), retrying in ${INTERVAL}s..."
                sleep "${INTERVAL}"
            fi
        done
    ) &
fi

# Start nginx
echo "Starting nginx..."
exec nginx -g "daemon off;"
