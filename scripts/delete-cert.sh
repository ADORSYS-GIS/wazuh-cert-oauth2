#!/bin/bash
# /var/ossec/active-response/bin/delete-cert.sh

CERT="/var/ossec/etc/sslagent.cert"
KEY="/var/ossec/etc/sslagent.key"
AR_LOG="/var/ossec/logs/active-responses.log"
TAG="delete-cert"

# Log function
log() {
    local level="$1"
    local msg="$2"
    echo "$(date '+%Y/%m/%d %H:%M:%S') $TAG: [$level] $msg" >> "$AR_LOG"
}

log "INFO" "Active response triggered via API"

# Read the JSON input from stdin (required for AR)
read -r INPUT_JSON

log "DEBUG" "Received input: ${INPUT_JSON:0:200}..."   # Truncate for log

# Cleanup certificates
deleted=0
for file in "$CERT" "$KEY"; do
    if [ -f "$file" ]; then
        if rm -f "$file"; then
            log "INFO" "Successfully deleted $file"
            deleted=$((deleted + 1))
        else
            log "ERROR" "Failed to delete $file"
        fi
    else
        log "WARN" "$file not found (already deleted?)"
    fi
done

log "INFO" "Finished. Deleted $deleted certificate file(s)."

exit 0