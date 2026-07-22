#!/usr/bin/env bash
# =============================================================================
# migrate-ledger.sh — Migrate wazuh-cert-oauth2 ledger CSV from 8-column
# (no wazuh_agent_name) to 9-column format by correlating ledger entries with
# Wazuh manager agents.
#
# Strategy:
#   Tier 1 — Keycloak name prefix: query the Keycloak Admin API for the
#            user's display name, compute the expected agent-name prefix,
#            and match against Wazuh agent names.  This is the most reliable
#            method because agent names are deterministic from user names.
#   Tier 2 — Timestamp proximity (fallback): when Keycloak is unavailable
#            or the user cannot be found, match by cert issuance timestamp
#            proximity to agent registration timestamp within a ±5 s window.
#   Fallback — Unresolved entries are written to unresolved.csv for manual
#              review.
#
# Usage:
#   All of the following MUST be set in the environment.
#
#   For admin password grant (default):
#     export KEYCLOAK_ADMIN_URL="http://keycloak:8004"
#     export KEYCLOAK_ADMIN_USER="admin"
#     export KEYCLOAK_ADMIN_PASSWORD="..."
#     export KEYCLOAK_REALM="dev"
#
#   For service account (client credentials):
#     export KEYCLOAK_AUTH_METHOD="client_credentials"
#     export KEYCLOAK_ADMIN_URL="http://keycloak:8004"
#     export KEYCLOAK_CLIENT_ID="test-client-secret"
#     export KEYCLOAK_CLIENT_SECRET="..."
#     export KEYCLOAK_REALM="dev"
#
#   export WAZUH_MANAGER_URL="https://wazuh-manager:55000"
#   export WAZUH_API_USER="wazuh-wui"
#   export WAZUH_API_PASSWORD="..."
#
#   ./migrate-ledger.sh ledger-backup.csv ledger-migrated.csv
#
# Dependencies: curl, jq, bash 4+
# =============================================================================

set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
# Wazuh credentials — MUST be set.
: "${WAZUH_MANAGER_URL:?must be set}"
: "${WAZUH_API_USER:?must be set}"
: "${WAZUH_API_PASSWORD:?must be set}"

# Keycloak — MUST be set.  Two auth methods supported:
#   password (default)       → KEYCLOAK_ADMIN_USER + KEYCLOAK_ADMIN_PASSWORD
#   client_credentials       → KEYCLOAK_CLIENT_ID   + KEYCLOAK_CLIENT_SECRET
: "${KEYCLOAK_ADMIN_URL:?must be set}"
: "${KEYCLOAK_REALM:?must be set}"
: "${KEYCLOAK_AUTH_METHOD:=password}"

if [[ "$KEYCLOAK_AUTH_METHOD" == "client_credentials" ]]; then
    : "${KEYCLOAK_CLIENT_ID:?must be set when KEYCLOAK_AUTH_METHOD=client_credentials}"
    : "${KEYCLOAK_CLIENT_SECRET:?must be set when KEYCLOAK_AUTH_METHOD=client_credentials}"
else
    : "${KEYCLOAK_ADMIN_USER:?must be set}"
    : "${KEYCLOAK_ADMIN_PASSWORD:?must be set}"
fi

# Optional tuning knobs (sensible defaults).
: "${WAZUH_TLS_VERIFY:=false}"
: "${KEYCLOAK_TLS_VERIFY:=false}"
: "${TIMESTAMP_WINDOW:=5}"
: "${TIMESTAMP_WINDOW_EXTENDED:=30}"

INPUT="${1:?Usage: $0 <input.csv> [output.csv] [unresolved.csv] [report.txt]}"
OUTPUT="${2:-ledger-migrated.csv}"
UNRESOLVED="${3:-unresolved.csv}"
REPORT="${4:-migration-report.txt}"

# ── Helpers ─────────────────────────────────────────────────────────────────
CURL_WAZUH=(curl -sS --max-time 30)
CURL_KC=(curl -sS --max-time 30)

if [[ "$WAZUH_TLS_VERIFY" == "false" ]]; then
    CURL_WAZUH+=(-k)
elif [[ -n "$WAZUH_TLS_VERIFY" && "$WAZUH_TLS_VERIFY" != "true" ]]; then
    CURL_WAZUH+=(--cacert "$WAZUH_TLS_VERIFY")
fi

if [[ "$KEYCLOAK_TLS_VERIFY" == "false" ]]; then
    CURL_KC+=(-k)
elif [[ -n "$KEYCLOAK_TLS_VERIFY" && "$KEYCLOAK_TLS_VERIFY" != "true" ]]; then
    CURL_KC+=(--cacert "$KEYCLOAK_TLS_VERIFY")
fi

log()  { echo "[$(date '+%H:%M:%S')] $*" >&2; }
die()  { log "FATAL: $*"; exit 1; }

# ── Step 1: Authenticate with Wazuh Manager ─────────────────────────────────
log "Authenticating with Wazuh Manager..."
WAZUH_TOKEN=$( "${CURL_WAZUH[@]}" \
    -X POST "${WAZUH_MANAGER_URL}/security/user/authenticate" \
    -H "Content-Type: application/json" \
    -u "${WAZUH_API_USER}:${WAZUH_API_PASSWORD}" \
    | jq -r '.data.token // empty' )

if [[ -z "$WAZUH_TOKEN" ]]; then
    die "Failed to authenticate with Wazuh Manager"
fi
log "Wazuh authentication successful"

# ── Step 2: Fetch all agents from Wazuh Manager ─────────────────────────────
log "Fetching agents from Wazuh Manager..."
WAZUH_AGENTS_JSON=$( "${CURL_WAZUH[@]}" \
    -X GET "${WAZUH_MANAGER_URL}/agents" \
    -H "Authorization: Bearer ${WAZUH_TOKEN}" \
    -H "Content-Type: application/json" )

AGENT_COUNT=$(echo "$WAZUH_AGENTS_JSON" | jq '.data.affected_items | length')
log "Retrieved $AGENT_COUNT agents from Wazuh Manager"

if [[ "$AGENT_COUNT" -eq 0 ]]; then
    die "No agents found in Wazuh Manager — nothing to match"
fi

# ── Step 3: Parse agents into a temp file (id|name|dateAdd_unix) ────────────
AGENTS_TMP=$(mktemp)
trap 'rm -f "$AGENTS_TMP"' EXIT

echo "$WAZUH_AGENTS_JSON" | jq -r '
    .data.affected_items[]
    | [.id, .name, (.dateAdd // "")]
    | @tsv
' | while IFS=$'\t' read -r agent_id agent_name date_add; do
    if [[ -n "$date_add" ]]; then
        date_add_unix=$(date -d "$date_add" +%s 2>/dev/null || echo "0")
    else
        date_add_unix="0"
    fi
    echo "${agent_id}|${agent_name}|${date_add_unix}"
done > "$AGENTS_TMP"

log "Parsed $(wc -l < "$AGENTS_TMP") agents with timestamps"

# ── Step 4: Authenticate with Keycloak Admin API ────────────────────────────
log "Authenticating with Keycloak Admin API (method: ${KEYCLOAK_AUTH_METHOD})..."

if [[ "$KEYCLOAK_AUTH_METHOD" == "client_credentials" ]]; then
    KC_TOKEN=$( "${CURL_KC[@]}" \
        -X POST "${KEYCLOAK_ADMIN_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials" \
        -d "client_id=${KEYCLOAK_CLIENT_ID}" \
        -d "client_secret=${KEYCLOAK_CLIENT_SECRET}" \
        | jq -r '.access_token // empty' )
else
    KC_TOKEN=$( "${CURL_KC[@]}" \
        -X POST "${KEYCLOAK_ADMIN_URL}/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" \
        -d "username=${KEYCLOAK_ADMIN_USER}" \
        -d "password=${KEYCLOAK_ADMIN_PASSWORD}" \
        | jq -r '.access_token // empty' )
fi

if [[ -z "$KC_TOKEN" ]]; then
    log "WARNING: Keycloak admin authentication failed — Tier 2 tiebreaking unavailable"
    KC_AVAILABLE=false
else
    log "Keycloak admin authentication successful"
    KC_AVAILABLE=true
fi

# ── Step 5: Keycloak user lookup helper ─────────────────────────────────────
lookup_keycloak_user() {
    local uuid="$1"
    if [[ "$KC_AVAILABLE" != "true" ]]; then
        echo "UNKNOWN"
        return
    fi

    local user_json
    user_json=$( "${CURL_KC[@]}" \
        -X GET "${KEYCLOAK_ADMIN_URL}/admin/realms/${KEYCLOAK_REALM}/users/${uuid}" \
        -H "Authorization: Bearer ${KC_TOKEN}" \
        -H "Content-Type: application/json" 2>/dev/null || true )

    local first last username display
    first=$(echo "$user_json" | jq -r '.firstName // ""')
    last=$(echo "$user_json" | jq -r '.lastName // ""')
    username=$(echo "$user_json" | jq -r '.username // ""')

    if [[ -n "$first" || -n "$last" ]]; then
        display="${first} ${last}"
        # trim whitespace
        display="${display#"${display%%[![:space:]]*}"}"
        display="${display%"${display##*[![:space:]]}"}"
    elif [[ -n "$username" ]]; then
        display="$username"
    else
        echo "UNKNOWN"
        return
    fi
    echo "$display"
}

# ── Step 6: Sanitize name for prefix matching ───────────────────────────────
sanitize_name() {
    echo "$1" | sed -E '
        s/[^a-zA-Z0-9]/-/g
        s/--+/-/g
        s/^-+//g
        s/-+$//g
    '
}

# ── Step 7: Find matching agent for a ledger entry ──────────────────────────
# Arguments: subject issued_at_unix
# Output: "agent_name|match_tier" or "|unmatched_reason"
find_agent_match() {
    local subject="$1"
    local issued_at="$2"

    # ── Tier 1: Keycloak name prefix matching ──
    # Most reliable: agent names are deterministic from Keycloak user names.
    if [[ "$KC_AVAILABLE" == "true" ]]; then
        local kc_name
        kc_name=$(lookup_keycloak_user "$subject")
        if [[ "$kc_name" != "UNKNOWN" ]]; then
            local prefix
            prefix=$(sanitize_name "$kc_name")

            # Search ALL agents by prefix
            local matched=()
            while IFS='|' read -r aid aname adate; do
                if [[ "$aname" == "${prefix}-"* ]]; then
                    matched+=("${aid}|${aname}|${adate}")
                fi
            done < "$AGENTS_TMP"

            if [[ ${#matched[@]} -eq 1 ]]; then
                local name="${matched[0]#*|}"; name="${name%%|*}"
                echo "${name}|tier1_keycloak_prefix"
                return
            elif [[ ${#matched[@]} -gt 1 ]]; then
                # Multiple prefix matches — use timestamp proximity as tiebreaker
                local best_name="" best_diff=999999
                for mentry in "${matched[@]}"; do
                    local mname="${mentry#*|}"; mname="${mname%%|*}"
                    local mdate="${mentry##*|}"
                    if [[ "$mdate" != "0" ]]; then
                        local diff=$(( issued_at - mdate ))
                        diff=${diff#-}
                        if (( diff < best_diff )); then
                            best_diff=$diff
                            best_name="$mname"
                        fi
                    fi
                done
                if [[ -n "$best_name" ]]; then
                    echo "${best_name}|tier1_keycloak_prefix_tiebreaker"
                    return
                fi
                echo "|unmatched_ambiguous_prefix"
                return
            fi

            # Try case-insensitive prefix match
            local prefix_lower="${prefix,,}"
            while IFS='|' read -r aid aname adate; do
                local aname_lower="${aname,,}"
                if [[ "$aname_lower" == "${prefix_lower}-"* ]]; then
                    matched+=("${aid}|${aname}|${adate}")
                fi
            done < "$AGENTS_TMP"

            if [[ ${#matched[@]} -eq 1 ]]; then
                local name="${matched[0]#*|}"; name="${name%%|*}"
                echo "${name}|tier1_keycloak_prefix_ci"
                return
            fi
        fi
    fi

    # ── Tier 2: Timestamp proximity (fallback) ──
    # Used when Keycloak is unavailable or user not found.
    local candidates=()
    while IFS='|' read -r aid aname adate; do
        if [[ "$adate" == "0" ]]; then continue; fi
        local diff=$(( issued_at - adate ))
        diff=${diff#-}  # absolute value
        if (( diff <= TIMESTAMP_WINDOW )); then
            candidates+=("${aid}|${aname}|${adate}|${diff}")
        fi
    done < "$AGENTS_TMP"

    if [[ ${#candidates[@]} -eq 1 ]]; then
        local name="${candidates[0]#*|}"; name="${name%%|*}"
        echo "${name}|tier2_timestamp"
        return
    fi

    # Extended window
    if [[ ${#candidates[@]} -eq 0 ]]; then
        while IFS='|' read -r aid aname adate; do
            if [[ "$adate" == "0" ]]; then continue; fi
            local diff=$(( issued_at - adate ))
            diff=${diff#-}
            if (( diff <= TIMESTAMP_WINDOW_EXTENDED )); then
                candidates+=("${aid}|${aname}|${adate}|${diff}")
            fi
        done < "$AGENTS_TMP"

        if [[ ${#candidates[@]} -eq 1 ]]; then
            local name="${candidates[0]#*|}"; name="${name%%|*}"
            echo "${name}|tier2_timestamp_extended"
            return
        fi
    fi

    # ── Unmatched ──
    if [[ "$KC_AVAILABLE" != "true" ]]; then
        echo "|unmatched_no_keycloak"
    elif [[ ${#candidates[@]} -gt 1 ]]; then
        echo "|unmatched_timestamp_tie"
    else
        echo "|unmatched_no_match"
    fi
}

# ── Step 8: Parse a single CSV line into fields (handles simple unquoted CSV) ─
# The ledger CSV has simple fields (UUIDs, hex, numbers) — no embedded commas.
parse_csv_line() {
    local line="$1"
    local -n _subject=$2
    local -n _serial=$3
    local -n _issued=$4
    local -n _revoked=$5
    local -n _revoked_at=$6
    local -n _reason=$7
    local -n _issuer=$8
    local -n _realm=$9

    IFS=',' read -r _subject _serial _issued _revoked _revoked_at _reason _issuer _realm <<< "$line"
    # Strip surrounding quotes if present
    _subject="${_subject#\"}"; _subject="${_subject%\"}"
    _serial="${_serial#\"}"; _serial="${_serial%\"}"
    _reason="${_reason#\"}"; _reason="${_reason%\"}"
    _issuer="${_issuer#\"}"; _issuer="${_issuer%\"}"
    _realm="${_realm#\"}"; _realm="${_realm%\"}"
}

# ── Step 9: Process the ledger CSV ──────────────────────────────────────────
log "Processing ledger CSV: $INPUT"

EXPECTED_HEADER="subject,serial_hex,issued_at_unix,revoked,revoked_at_unix,reason,issuer,realm,wazuh_agent_name"

# Initialize output files
echo "$EXPECTED_HEADER" > "$OUTPUT"
{
    echo "# Unresolved ledger entries (could not match to a Wazuh agent)"
    echo "subject,serial_hex,issued_at_unix,reason"
} > "$UNRESOLVED"
{
    echo "=== Migration Report ==="
    echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "Input: $INPUT"
    echo "Output: $OUTPUT"
    echo "Wazuh agents found: $AGENT_COUNT"
    echo "Keycloak available: $KC_AVAILABLE"
    echo ""
    printf "%-40s %-35s %-25s %s\n" "subject" "wazuh_agent_name" "match_tier" "issued_at"
    printf "%-40s %-35s %-25s %s\n" "-------" "----------------" "----------" "---------"
} > "$REPORT"

total=0
matched=0
unmatched=0
tier1_count=0
tier2_count=0
tier2_ext_count=0

first_line=true
while IFS= read -r line || [[ -n "$line" ]]; do
    if $first_line; then
        first_line=false
        continue
    fi
    [[ -z "$line" ]] && continue

    total=$(( total + 1 ))

    # Parse the CSV line
    subject=""; serial=""; issued=""; revoked=""; revoked_at=""; reason=""; issuer=""; realm=""
    parse_csv_line "$line" subject serial issued revoked revoked_at reason issuer realm

    # Find matching agent
    result=""; agent_name=""; match_tier=""
    result=$(find_agent_match "$subject" "$issued")
    agent_name="${result%%|*}"
    match_tier="${result#*|}"

    if [[ -n "$agent_name" ]]; then
        matched=$(( matched + 1 ))
        case "$match_tier" in
            tier1_*)                   tier1_count=$(( tier1_count + 1 )) ;;
            tier2_timestamp)           tier2_count=$(( tier2_count + 1 )) ;;
            tier2_timestamp_extended)  tier2_ext_count=$(( tier2_ext_count + 1 )) ;;
        esac

        echo "${subject},${serial},${issued},${revoked},${revoked_at},${reason},${issuer},${realm},${agent_name}" >> "$OUTPUT"
        printf "%-40s %-35s %-25s %s\n" "$subject" "$agent_name" "$match_tier" "$issued" >> "$REPORT"
    else
        unmatched=$(( unmatched + 1 ))
        echo "${subject},${serial},${issued},${match_tier}" >> "$UNRESOLVED"
        # Still write to output with empty agent_name (preserves data)
        echo "${subject},${serial},${issued},${revoked},${revoked_at},${reason},${issuer},${realm}," >> "$OUTPUT"
        printf "%-40s %-35s %-25s %s\n" "$subject" "(unmatched)" "$match_tier" "$issued" >> "$REPORT"
    fi
done < "$INPUT"

# ── Step 10: Summary ────────────────────────────────────────────────────────
{
    echo ""
    echo "=== Summary ==="
    echo "Total ledger entries:  $total"
    echo "Matched:               $matched"
    echo "  Tier 1 (Keycloak prefix):   $tier1_count"
    echo "  Tier 2 (timestamp ±${TIMESTAMP_WINDOW}s):     $tier2_count"
    echo "  Tier 2 (timestamp ±${TIMESTAMP_WINDOW_EXTENDED}s):  $tier2_ext_count"
    echo "Unmatched:             $unmatched"
    echo ""
    if [[ $unmatched -gt 0 ]]; then
        echo "WARNING: $unmatched entries could not be matched."
        echo "  Review $UNRESOLVED and update $OUTPUT before restoring."
    else
        echo "SUCCESS: All entries matched."
    fi
} >> "$REPORT"

cat "$REPORT"

log "Migration complete."
log "  Migrated CSV: $OUTPUT"
log "  Unresolved:   $UNRESOLVED"
log "  Report:       $REPORT"
