#!/bin/bash
# Origin-log jail for Cloudflare Free: append abusive IPs to an account IP List.
# BLOCK_BOTS must be a static rule:  ip.src in $jail_list
set -euo pipefail

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -c, --count <n>     Min total hits before an IP is looked up (default: ${HIT_THRESHOLD:-250})"
    echo "  -t, --target <name> Only process this domain from the matrix"
    echo "  -d, --dry-run       Look up and report; do not add anything to the list"
    echo "      --init-list     Create the Cloudflare IP list and exit"
    echo "  -h, --help          Show this help"
    exit 1
}

CREDENTIALS_FILE="${CLOUDFLARE_JAIL_ENV:-/etc/cloudflare-jail.env}"
ALLOW_FILE="${CLOUDFLARE_JAIL_ALLOW:-/etc/cloudflare-jail.allow}"
PATHS_FILE="${CLOUDFLARE_JAIL_PATHS:-/etc/cloudflare-jail.paths}"
CACHE_DIR="${CLOUDFLARE_JAIL_CACHE:-/var/cache/cloudflare-jail}"
LOCK_FILE="${CLOUDFLARE_JAIL_LOCK:-/var/lock/cloudflare-jail.lock}"

DRY_RUN=false
INIT_LIST=false
HIT_THRESHOLD=250
PROBE_THRESHOLD=10
SCORE_JAIL=50
SCORE_SUBNET=75
SCORE_GB_HOSTING=75
CACHE_TTL_DAYS=7
TARGET_DOMAIN=""
EMAIL_RECIPIENT=""
EMAIL_FROM="Cloudflare WAF Engine <security@cloudsentis.com>"
CLOUDFLARE_LIST_NAME="jail_list"

if [[ -f "$CREDENTIALS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$CREDENTIALS_FILE"
fi

# Trim CR/LF/spaces copied from Windows editors or quoted paste.
sanitize_secret() {
    local value="${1-}"
    value="${value%$'\r'}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    value="${value#\"}"
    value="${value%\"}"
    value="${value#\'}"
    value="${value%\'}"
    printf '%s' "$value"
}
ABUSEIPDB_API_KEY="$(sanitize_secret "${ABUSEIPDB_API_KEY-}")"
CLOUDFLARE_API_TOKEN="$(sanitize_secret "${CLOUDFLARE_API_TOKEN-}")"
CLOUDFLARE_ACCOUNT_ID="$(sanitize_secret "${CLOUDFLARE_ACCOUNT_ID-}")"
CLOUDFLARE_LIST_NAME="$(sanitize_secret "${CLOUDFLARE_LIST_NAME:-jail_list}")"
CLOUDFLARE_LIST_ID="$(sanitize_secret "${CLOUDFLARE_LIST_ID-}")"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--count) HIT_THRESHOLD="$2"; shift 2 ;;
        -t|--target) TARGET_DOMAIN="$2"; shift 2 ;;
        -d|--dry-run) DRY_RUN=true; shift 1 ;;
        --init-list) INIT_LIST=true; shift 1 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# log path -> domain name
declare -A DOMAIN_MATRIX
DOMAIN_MATRIX=(
    ["/var/log/httpd/beaconrcc.org.uk-access.log"]="beaconrcc.org.uk"
    ["/var/log/httpd/d60skiphire.com-access.log"]="d60skiphire.com"
    ["/var/log/httpd/stridemix.com-access.log"]="stridemix.com"
)

# Default probe fragments. Add the obscure login path on the server in $PATHS_FILE.
PROBE_PATTERNS=(
    "/xmlrpc.php"
    "/wp-login.php"
    "/wp-admin"
    "/wp-config"
    "/.env"
    "phpunit"
    "/vendor/phpunit"
)

if [[ -f "$PATHS_FILE" ]]; then
    while IFS= read -r extra || [[ -n "$extra" ]]; do
        extra="${extra%%#*}"
        extra="${extra%"${extra##*[![:space:]]}"}"
        extra="${extra#"${extra%%[![:space:]]*}"}"
        [[ -z "$extra" ]] && continue
        PROBE_PATTERNS+=("$extra")
    done < "$PATHS_FILE"
fi

iputil() {
    python3 - "$1" "$2" "${3:-}" "$ALLOW_FILE" <<'PY'
import ipaddress
import sys

cmd, value, extra, allow_file = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

CF_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

def parse_ip(raw):
    return ipaddress.ip_address(raw)

def networks_from_allow():
    nets = []
    try:
        with open(allow_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    nets.append(ipaddress.ip_network(line, strict=False))
    except FileNotFoundError:
        pass
    return nets

def should_skip(ip):
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return True
    if ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10"):
        return True
    if ip.version == 4:
        for cidr in CF_V4:
            if ip in ipaddress.ip_network(cidr):
                return True
    for net in networks_from_allow():
        if ip in net:
            return True
    return False

try:
    if cmd == "valid":
        parse_ip(value)
        sys.exit(0)
    ip = parse_ip(value)
    if cmd == "skip":
        sys.exit(0 if should_skip(ip) else 1)
    if cmd == "host":
        print(f"{ip}/32" if ip.version == 4 else f"{ip}/128")
        sys.exit(0)
    if cmd == "wrap":
        prefix = 24 if ip.version == 4 else 64
        print(str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False)))
        sys.exit(0)
    if cmd == "in":
        sys.exit(0 if ip in ipaddress.ip_network(extra, strict=False) else 1)
except Exception:
    sys.exit(2)
sys.exit(2)
PY
}

cf_api() {
    local method="$1"
    local url="$2"
    local data="${3:-}"
    if [[ -n "$data" ]]; then
        curl -sS -X "$method" "$url" \
            -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
            -H "Content-Type: application/json" \
            --data "$data"
    else
        curl -sS -X "$method" "$url" \
            -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
            -H "Content-Type: application/json"
    fi
}

verify_cloudflare_token() {
    local verify
    verify=$(curl -sS "https://api.cloudflare.com/client/v4/user/tokens/verify" \
        -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
        -H "Content-Type: application/json") || true
    if echo "$verify" | jq -e '.success == true and .result.status == "active"' >/dev/null 2>&1; then
        echo "Cloudflare token is active (length ${#CLOUDFLARE_API_TOKEN}, account ${CLOUDFLARE_ACCOUNT_ID})."
        return 0
    fi
    echo "Cloudflare token was rejected before any list call." >&2
    echo "Token length: ${#CLOUDFLARE_API_TOKEN}. Account ID length: ${#CLOUDFLARE_ACCOUNT_ID}." >&2
    echo "Create a *API Token* (not Global API Key) with Account → Account Filter Lists → Edit," >&2
    echo "scoped to this account, then put only the token value in CLOUDFLARE_API_TOKEN." >&2
    echo "$verify" | jq . >&2
    return 1
}

resolve_list_id() {
    if [[ -n "${CLOUDFLARE_LIST_ID:-}" ]]; then
        echo "$CLOUDFLARE_LIST_ID"
        return
    fi
    local payload
    payload=$(cf_api GET "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/rules/lists")
    if ! echo "$payload" | jq -e '.success == true' >/dev/null 2>&1; then
        echo "Failed to list Cloudflare IP lists:" >&2
        echo "$payload" | jq . >&2
        return 1
    fi
    echo "$payload" | jq -r --arg name "$CLOUDFLARE_LIST_NAME" '
        .result[]? | select(.name == $name and .kind == "ip") | .id
    ' | head -n 1
}

init_list() {
    local existing
    existing=$(resolve_list_id || true)
    if [[ -n "$existing" ]]; then
        echo "List '$CLOUDFLARE_LIST_NAME' already exists as $existing"
        echo "BLOCK_BOTS expression: ip.src in \$${CLOUDFLARE_LIST_NAME}"
        return
    fi
    local payload
    payload=$(jq -n \
        --arg name "$CLOUDFLARE_LIST_NAME" \
        --arg desc "Origin-log jail for BLOCK_BOTS" \
        '{kind:"ip", name:$name, description:$desc}')
    local resp
    resp=$(cf_api POST "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/rules/lists" "$payload")
    local id
    id=$(echo "$resp" | jq -r '.result.id // empty')
    if [[ -z "$id" ]]; then
        echo "Failed to create list:" >&2
        echo "$resp" | jq . >&2
        exit 1
    fi
    echo "Created list '$CLOUDFLARE_LIST_NAME' ($id)"
    echo "Set BLOCK_BOTS on each zone to: ip.src in \$${CLOUDFLARE_LIST_NAME}"
}

fetch_list_items() {
    local list_id="$1"
    local cursor=""
    local url resp
    : > "$EXISTING_ITEMS"
    while true; do
        if [[ -n "$cursor" ]]; then
            url="https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/rules/lists/${list_id}/items?cursor=${cursor}"
        else
            url="https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/rules/lists/${list_id}/items?per_page=500"
        fi
        resp=$(cf_api GET "$url")
        if ! echo "$resp" | jq -e '.success == true' >/dev/null 2>&1; then
            echo "Failed to fetch list items:" >&2
            echo "$resp" | jq . >&2
            return 1
        fi
        echo "$resp" | jq -r '.result[]?.ip // empty' >> "$EXISTING_ITEMS"
        cursor=$(echo "$resp" | jq -r '.result_info.cursors.after // empty')
        [[ -z "$cursor" ]] && break
    done
    sort -u -o "$EXISTING_ITEMS" "$EXISTING_ITEMS"
}

already_listed() {
    local cidr="$1"
    grep -Fxq "$cidr" "$EXISTING_ITEMS"
}

cache_get() {
    local ip="$1"
    local cache="$CACHE_DIR/abuseipdb.cache"
    [[ -f "$cache" ]] || return 1
    python3 - "$ip" "$cache" "$CACHE_TTL_DAYS" <<'PY'
import sys, time
ip, path, ttl_days = sys.argv[1], sys.argv[2], int(sys.argv[3])
cutoff = time.time() - ttl_days * 86400
with open(path, encoding="utf-8") as fh:
    for line in fh:
        parts = line.rstrip("\n").split("\t")
        if len(parts) < 6:
            continue
        if parts[0] == ip and float(parts[5]) >= cutoff:
            print("\t".join(parts[1:5]))
            sys.exit(0)
sys.exit(1)
PY
}

cache_put() {
    local ip="$1" score="$2" usage="$3" isp="$4" country="$5"
    mkdir -p "$CACHE_DIR"
    python3 - "$CACHE_DIR/abuseipdb.cache" "$ip" "$score" "$usage" "$isp" "$country" <<'PY'
import os, sys, time
path, ip, score, usage, isp, country = sys.argv[1:7]
lines = []
if os.path.exists(path):
    with open(path, encoding="utf-8") as fh:
        lines = [ln for ln in fh if not ln.startswith(ip + "\t")]
lines.append(f"{ip}\t{score}\t{usage}\t{isp}\t{country}\t{time.time():.0f}\n")
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    fh.writelines(lines[-5000:])
os.replace(tmp, path)
PY
}

lookup_abuse() {
    local ip="$1"
    local cached
    if cached=$(cache_get "$ip"); then
        echo "$cached"
        return 0
    fi
    local resp
    resp=$(curl -sS -G https://api.abuseipdb.com/api/v2/check \
        --data-urlencode "ipAddress=$ip" \
        -d maxAgeInDays=30 \
        -H "Key: ${ABUSEIPDB_API_KEY}" \
        -H "Accept: application/json") || true
    if echo "$resp" | jq -e '.errors? | length > 0' >/dev/null 2>&1; then
        echo "AbuseIPDB error for $ip: $(echo "$resp" | jq -r '.errors[0].detail // .errors[0].message // "unknown"')" >&2
        return 1
    fi
    local score usage isp country
    score=$(echo "$resp" | jq -r '.data.abuseConfidenceScore // empty')
    usage=$(echo "$resp" | jq -r '.data.usageType // "Unknown"')
    isp=$(echo "$resp" | jq -r '.data.isp // "Unknown"')
    country=$(echo "$resp" | jq -r '.data.countryCode // "XX"')
    if [[ -z "$score" || ! "$score" =~ ^[0-9]+$ ]]; then
        echo "AbuseIPDB returned no score for $ip" >&2
        return 1
    fi
    cache_put "$ip" "$score" "$usage" "$isp" "$country"
    echo -e "${score}\t${usage}\t${isp}\t${country}"
}

is_hosting() {
    local usage="$1"
    [[ "$usage" == *"Data Center"* || "$usage" == *"Data Centre"* || "$usage" == *"Hosting"* ]]
}

decide_cidr() {
    local ip="$1" score="$2" usage="$3" country="$4"
    country=$(echo "$country" | tr '[:lower:]' '[:upper:]')

    if [[ "$country" == "GB" ]]; then
        if is_hosting "$usage" && [[ "$score" -ge "$SCORE_GB_HOSTING" ]]; then
            iputil host "$ip"
            return 0
        fi
        return 1
    fi

    if [[ "$score" -lt "$SCORE_JAIL" ]]; then
        return 1
    fi

    if is_hosting "$usage" && [[ "$score" -ge "$SCORE_SUBNET" ]]; then
        iputil wrap "$ip"
        return 0
    fi

    iputil host "$ip"
}

skip_reason() {
    local score="$1" usage="$2" country="$3"
    country=$(echo "$country" | tr '[:lower:]' '[:upper:]')
    if [[ "$country" == "GB" ]]; then
        if ! is_hosting "$usage"; then
            echo "GB residential/ISP (not jailed)"
            return
        fi
        echo "GB hosting score ${score} < ${SCORE_GB_HOSTING}"
        return
    fi
    echo "score ${score} < ${SCORE_JAIL}"
}

queued_cidr() {
    awk -F '\t' -v c="$1" '$1 == c { found=1; exit } END { exit !found }' "$2"
}

parse_log() {
    local log_path="$1"
    local domain="$2"
    # $2 is %h — visitor IP after mod_remoteip. $1 is %{c}a (Cloudflare edge).
    awk -v domain="$domain" '
    {
        ip = $2
        if (ip == "" || ip == "-") next
        req = ""
        if (match($0, /"(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH) [^" ]+/)) {
            req = substr($0, RSTART, RLENGTH)
        }
        print ip "\t" req
    }
    ' "$log_path"
}

count_candidates() {
    local log_path="$1"
    local domain="$2"
    local awk_pat=""
    local p
    for p in "${PROBE_PATTERNS[@]}"; do
        awk_pat+="${awk_pat:+|}${p}"
    done

    # One awk pass: count hits and probes, then emit IPs that meet either
    # threshold. The previous bash loop spawned awk once per unique IP and
    # scanned probe counts from scratch — O(unique_ips * log_size) — which
    # looked like a hang on busy access logs (high CPU in bash, tee idle).
    parse_log "$log_path" "$domain" | awk -F '\t' \
        -v pat="$awk_pat" \
        -v hit_th="$HIT_THRESHOLD" \
        -v probe_th="$PROBE_THRESHOLD" '
        {
            ip = $1
            if (ip == "") next
            hits[ip]++
            if (pat != "" && $2 ~ pat) probes[ip]++
        }
        END {
            for (ip in hits) {
                p = (ip in probes) ? probes[ip] + 0 : 0
                if (hits[ip] + 0 >= hit_th + 0 || p >= probe_th + 0)
                    printf "%d\t%d\t%s\n", hits[ip], p, ip
            }
        }
    ' | sort -t $'\t' -k1,1nr -k2,2nr
}

queue_cidr() {
    local cidr="$1" comment="$2"
    if already_listed "$cidr"; then
        echo "      already on list: $cidr"
        return
    fi
    if queued_cidr "$cidr" "$NEW_BLOCKS_LIST"; then
        echo "      already queued: $cidr"
        return
    fi
    printf '%s\t%s\n' "$cidr" "$comment" >> "$NEW_BLOCKS_LIST"
    echo "      queued: $cidr"
}

push_list_items() {
    local list_id="$1"
    if [[ ! -s "$NEW_BLOCKS_LIST" ]]; then
        echo "No new list items."
        return
    fi
    local unique
    unique=$(mktemp)
    awk -F '\t' '$1 != "" && !seen[$1]++' "$NEW_BLOCKS_LIST" > "$unique"
    mv "$unique" "$NEW_BLOCKS_LIST"
    local payload="[]" cidr comment
    while IFS=$'\t' read -r cidr comment; do
        [[ -z "$cidr" ]] && continue
        payload=$(jq -c --arg ip "$cidr" --arg c "${comment:0:140}" \
            '. + [{ip: $ip, comment: $c}]' <<< "$payload")
    done < "$NEW_BLOCKS_LIST"

    if [[ "$DRY_RUN" = true ]]; then
        echo "[DRY RUN] Would add $(echo "$payload" | jq 'length') item(s) to $CLOUDFLARE_LIST_NAME"
        echo "$payload" | jq -r '.[] | "  " + .ip + "  " + .comment'
        return
    fi

    local resp
    resp=$(cf_api POST \
        "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/rules/lists/${list_id}/items" \
        "$payload")
    if ! echo "$resp" | jq -e '.success == true' >/dev/null; then
        echo "Cloudflare list update failed:" >&2
        echo "$resp" | jq . >&2
        return 1
    fi
    echo "Submitted $(echo "$payload" | jq 'length') item(s) to $CLOUDFLARE_LIST_NAME"
}

# Allow tests to `source` this file for count_candidates without hitting APIs.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

for cmd in curl jq python3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing dependency: $cmd" >&2
        exit 1
    fi
done

if [[ -z "${ABUSEIPDB_API_KEY:-}" || -z "${CLOUDFLARE_API_TOKEN:-}" || -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
    echo "Set ABUSEIPDB_API_KEY, CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID in $CREDENTIALS_FILE" >&2
    exit 1
fi

if [[ "$INIT_LIST" = true ]]; then
    verify_cloudflare_token
    init_list
    exit 0
fi

verify_cloudflare_token

mkdir -p "$CACHE_DIR" "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "Another cloudflare-jail run is in progress." >&2
    exit 1
fi

LIST_ID="$(resolve_list_id || true)"
if [[ -z "$LIST_ID" ]]; then
    echo "IP list '$CLOUDFLARE_LIST_NAME' not found. Create it in the dashboard or run: $0 --init-list" >&2
    exit 1
fi

EXISTING_ITEMS=$(mktemp)
NEW_BLOCKS_LIST=$(mktemp)
CANDIDATES_FILE=$(mktemp)
EMAIL_BODY=$(mktemp)
trap 'rm -f "$EXISTING_ITEMS" "$NEW_BLOCKS_LIST" "$CANDIDATES_FILE"' EXIT

fetch_list_items "$LIST_ID"

(
echo "====================================================================="
echo "Starting origin-log jail: $(date)"
echo "List: \$${CLOUDFLARE_LIST_NAME} ($LIST_ID)  dry-run=$DRY_RUN"
echo "====================================================================="

for log_path in "${!DOMAIN_MATRIX[@]}"; do
    DOMAIN_NAME="${DOMAIN_MATRIX[$log_path]}"
    if [[ -n "$TARGET_DOMAIN" && "$DOMAIN_NAME" != "$TARGET_DOMAIN" ]]; then
        continue
    fi

    echo ""
    echo "====================================================================="
    echo "Domain: $DOMAIN_NAME"
    echo "Log:    $log_path"
    echo "====================================================================="

    if [[ ! -f "$log_path" ]]; then
        echo "   Log file not found, skipping."
        continue
    fi

    echo "   Scanning log for candidates (hits>=${HIT_THRESHOLD} or probes>=${PROBE_THRESHOLD})..."
    count_candidates "$log_path" "$DOMAIN_NAME" > "$CANDIDATES_FILE"
    echo "   Candidates: $(wc -l < "$CANDIDATES_FILE" | tr -d ' ')"

    while IFS=$'\t' read -r hits probe ip; do
        echo "   -------------------------------------------------------------"
        echo "   IP $ip  hits=$hits  probes=$probe"

        if ! iputil valid "$ip"; then
            echo "      skip: not an IP"
            continue
        fi
        if iputil skip "$ip"; then
            echo "      skip: private, Cloudflare edge, or allowlisted"
            continue
        fi

        if ! intel=$(lookup_abuse "$ip"); then
            echo "      skip: AbuseIPDB lookup failed"
            continue
        fi
        IFS=$'\t' read -r score usage isp country <<< "$intel"
        echo "      AbuseIPDB score=${score}% country=${country} usage=${usage} isp=${isp}"

        if ! cidr=$(decide_cidr "$ip" "$score" "$usage" "$country"); then
            echo "      skip: $(skip_reason "$score" "$usage" "$country")"
            continue
        fi

        queue_cidr "$cidr" "${DOMAIN_NAME} score ${score} ${country} ${usage}"
    done < "$CANDIDATES_FILE"
done

echo ""
echo "====================================================================="
push_list_items "$LIST_ID"
echo "Finished: $(date)"
echo "====================================================================="
) | tee "$EMAIL_BODY"

if [[ -n "$EMAIL_RECIPIENT" && -s "$EMAIL_BODY" ]] && command -v mailx >/dev/null 2>&1; then
    if [[ "$DRY_RUN" = true ]]; then
        SUBJECT="Cloudflare jail summary [DRY RUN]"
    else
        SUBJECT="Cloudflare jail summary [LIVE]"
    fi
    mailx -r "$EMAIL_FROM" -s "$SUBJECT" "$EMAIL_RECIPIENT" < "$EMAIL_BODY" || true
fi
rm -f "$EMAIL_BODY"
