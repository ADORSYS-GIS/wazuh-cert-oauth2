#!/bin/bash
# /Library/Ossec/active-response/bin/delete-cert.sh

CERT="/Library/Ossec/etc/sslagent.cert"
KEY="/Library/Ossec/etc/sslagent.key"
AR_LOG="/Library/Ossec/logs/active-responses.log"
TAG="delete-cert"

log() {
    local level="$1"
    local msg="$2"
    echo "$(date '+%Y/%m/%d %H:%M:%S') $TAG: [$level] $msg" >> "$AR_LOG"
    return 0
}

log "INFO" "Active response triggered via API"

read -r INPUT_JSON
log "DEBUG" "Received input: ${INPUT_JSON:0:200}..."

deleted=0
for file in "$CERT" "$KEY"; do
    if [[ -f "$file" ]]; then
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
