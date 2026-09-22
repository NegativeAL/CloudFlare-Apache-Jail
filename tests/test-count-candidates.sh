#!/bin/bash
# Unit/perf checks for candidate counting and jail-decision helpers.
# Does not call Cloudflare or AbuseIPDB.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/cloudflare-jail.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0

assert_eq() {
    local got="$1" want="$2" msg="$3"
    if [[ "$got" == "$want" ]]; then
        echo "PASS  $msg"
        PASS=$((PASS + 1))
    else
        echo "FAIL  $msg"
        echo "      got:  $got"
        echo "      want: $want"
        FAIL=$((FAIL + 1))
    fi
}

assert_ok() {
    local msg="$1"
    echo "PASS  $msg"
    PASS=$((PASS + 1))
}

assert_fail_msg() {
    local msg="$1"
    echo "FAIL  $msg"
    FAIL=$((FAIL + 1))
}

# Pull helper functions without running the script body (API calls, flock, etc).
awk '
    $0 == "iputil() {" { p=1 }
    p && $0 == "queue_cidr() {" { exit }
    p { print }
' "$SCRIPT" > "$TMP/helpers.sh"
# shellcheck disable=SC1091
source "$TMP/helpers.sh"

HIT_THRESHOLD=250
PROBE_THRESHOLD=10
SCORE_JAIL=50
SCORE_SUBNET=75
SCORE_GB_HOSTING=75
ALLOW_FILE="$TMP/allow"
: > "$ALLOW_FILE"
PROBE_PATTERNS=(
    "/xmlrpc.php"
    "/wp-login.php"
    "/wp-admin"
    "/wp-config"
    "/.env"
    "phpunit"
    "/vendor/phpunit"
)

log_line() {
    local ip="$1" path="$2"
    printf '172.64.0.1 %s - - [22/Sep/2026:00:00:00 +0000] "GET %s HTTP/1.1" 200 100 "-" "Mozilla/5.0" 123\n' "$ip" "$path"
}

# Legacy algorithm: one awk process per unique IP. Used only to reproduce the hang
# and as a correctness oracle on small logs.
count_candidates_legacy() {
    local log_path="$1"
    local domain="$2"
    local parsed hits_file probe_file
    parsed=$(mktemp)
    hits_file=$(mktemp)
    probe_file=$(mktemp)
    parse_log "$log_path" "$domain" > "$parsed"

    awk -F '\t' '{c[$1]++} END {for (ip in c) print c[ip], ip}' "$parsed" \
        | sort -nr > "$hits_file"

    if ((${#PROBE_PATTERNS[@]})); then
        local awk_pat=""
        local p
        for p in "${PROBE_PATTERNS[@]}"; do
            awk_pat+="${awk_pat:+|}${p}"
        done
        awk -F '\t' -v pat="$awk_pat" '
            $2 ~ pat { c[$1]++ }
            END { for (ip in c) print c[ip], ip }
        ' "$parsed" | sort -nr > "$probe_file"
    fi

    declare -A SEEN=()
    local hits ip probe
    while read -r hits ip; do
        [[ -z "${ip:-}" ]] && continue
        probe=$(awk -v ip="$ip" '$2 == ip { print $1; exit }' "$probe_file")
        probe="${probe:-0}"
        if [[ "$hits" -ge "$HIT_THRESHOLD" || "$probe" -ge "$PROBE_THRESHOLD" ]]; then
            if [[ -z "${SEEN[$ip]:-}" ]]; then
                echo -e "${hits}\t${probe}\t${ip}"
                SEEN[$ip]=1
            fi
        fi
    done < "$hits_file"

    rm -f "$parsed" "$hits_file" "$probe_file"
}

# --- Thresholds (small log) -------------------------------------------------

SMALL_LOG="$TMP/small-access.log"
: > "$SMALL_LOG"

# High total hits, no probes.
for _ in $(seq 1 250); do log_line "198.51.100.10" "/" >> "$SMALL_LOG"; done
# Just under hit threshold, no probes — must be omitted.
for _ in $(seq 1 249); do log_line "198.51.100.11" "/" >> "$SMALL_LOG"; done
# Probe threshold met, low total hits.
for _ in $(seq 1 10); do log_line "198.51.100.12" "/wp-login.php" >> "$SMALL_LOG"; done
# Probes just under threshold.
for _ in $(seq 1 9); do log_line "198.51.100.13" "/xmlrpc.php" >> "$SMALL_LOG"; done
# Both thresholds met.
for _ in $(seq 1 200); do log_line "198.51.100.14" "/" >> "$SMALL_LOG"; done
for _ in $(seq 1 50); do log_line "198.51.100.14" "/.env" >> "$SMALL_LOG"; done
# Noise.
for i in $(seq 1 20); do log_line "203.0.113.$i" "/" >> "$SMALL_LOG"; done

NEW_OUT="$TMP/new.tsv"
OLD_OUT="$TMP/old.tsv"
count_candidates "$SMALL_LOG" "example.test" > "$NEW_OUT"
count_candidates_legacy "$SMALL_LOG" "example.test" > "$OLD_OUT"

sort -k3,3 "$NEW_OUT" > "$TMP/new.sorted"
sort -k3,3 "$OLD_OUT" > "$TMP/old.sorted"
if cmp -s "$TMP/new.sorted" "$TMP/old.sorted"; then
    assert_ok "small log: new candidate set matches legacy"
else
    assert_fail_msg "small log: candidate set differs from legacy"
    diff -u "$TMP/old.sorted" "$TMP/new.sorted" || true
fi

assert_eq "$(awk '$3=="198.51.100.10"{print $1,$2}' "$NEW_OUT")" "250 0" "high hits, no probes"
assert_eq "$(awk '$3=="198.51.100.11"{print}' "$NEW_OUT")" "" "249 hits omitted"
assert_eq "$(awk '$3=="198.51.100.12"{print $1,$2}' "$NEW_OUT")" "10 10" "probe threshold met"
assert_eq "$(awk '$3=="198.51.100.13"{print}' "$NEW_OUT")" "" "9 probes omitted"
assert_eq "$(awk '$3=="198.51.100.14"{print $1,$2}' "$NEW_OUT")" "250 50" "hits and probes both counted"
assert_eq "$(wc -l < "$NEW_OUT" | tr -d ' ')" "3" "exactly three candidates"

# Sorted by hits desc.
read -r first_hits _ first_ip <<< "$(head -n1 "$NEW_OUT" | tr '\t' ' ')"
if [[ "$first_hits" == "250" && ( "$first_ip" == "198.51.100.10" || "$first_ip" == "198.51.100.14" ) ]]; then
    assert_ok "candidates sorted by hits descending"
else
    assert_fail_msg "expected highest-hit IP first, got hits=$first_hits ip=$first_ip"
fi

# Empty probe-pattern list still filters on hits.
PROBE_PATTERNS=()
count_candidates "$SMALL_LOG" "example.test" > "$TMP/no-probe.tsv"
PROBE_PATTERNS=(
    "/xmlrpc.php" "/wp-login.php" "/wp-admin" "/wp-config" "/.env" "phpunit" "/vendor/phpunit"
)
assert_eq "$(awk '$3=="198.51.100.12"{print}' "$TMP/no-probe.tsv")" "" "no probe patterns: low-hit scanner omitted"
assert_eq "$(awk '$3=="198.51.100.10"{print $1,$2}' "$TMP/no-probe.tsv")" "250 0" "no probe patterns: high hits still counted"

# --- Dry-run style pipeline (tee) -------------------------------------------

CANDIDATES_FILE="$TMP/candidates.tsv"
EMAIL_BODY="$TMP/email.body"
PIPELINE_LOG="$TMP/pipeline.log"
(
    echo "Domain: example.test"
    echo "Log:    $SMALL_LOG"
    echo "   Scanning log for candidates (hits>=${HIT_THRESHOLD} or probes>=${PROBE_THRESHOLD})..."
    count_candidates "$SMALL_LOG" "example.test" > "$CANDIDATES_FILE"
    echo "   Candidates: $(wc -l < "$CANDIDATES_FILE" | tr -d ' ')"
    while IFS=$'\t' read -r hits probe ip; do
        echo "   IP $ip  hits=$hits  probes=$probe"
    done < "$CANDIDATES_FILE"
) | tee "$EMAIL_BODY" > "$PIPELINE_LOG"

if grep -q "Scanning log for candidates" "$EMAIL_BODY" \
    && grep -q "Candidates: 3" "$EMAIL_BODY" \
    && grep -q "IP 198.51.100.10" "$EMAIL_BODY"; then
    assert_ok "dry-run pipeline emits scan progress and IPs through tee"
else
    assert_fail_msg "dry-run pipeline missing expected tee output"
    cat "$EMAIL_BODY"
fi

# --- Large log: new path finishes quickly; legacy is the hang ---------------

LARGE_LOG="$TMP/large-access.log"
python3 - "$LARGE_LOG" <<'PY'
import sys
path = sys.argv[1]
# ~25k unique IPs, ~50k lines. Legacy spawns awk once per unique IP.
with open(path, "w", encoding="utf-8") as fh:
    def line(ip, url):
        fh.write(
            f'172.64.0.1 {ip} - - [22/Sep/2026:00:00:00 +0000] '
            f'"GET {url} HTTP/1.1" 200 100 "-" "Mozilla/5.0" 123\n'
        )
    for a in range(100):
        for b in range(250):
            line(f"203.0.{a}.{b}", "/")
    for _ in range(250):
        line("198.51.100.200", "/")
    for _ in range(12):
        line("198.51.100.201", "/wp-admin/index.php")
PY

echo "Timing new count_candidates on large log..."
START=$(date +%s%N)
count_candidates "$LARGE_LOG" "example.test" > "$TMP/large-new.tsv"
END=$(date +%s%N)
NEW_MS=$(( (END - START) / 1000000 ))
echo "  new: ${NEW_MS}ms, $(wc -l < "$TMP/large-new.tsv" | tr -d ' ') candidates"

if (( NEW_MS < 15000 )); then
    assert_ok "large log counted in ${NEW_MS}ms (<15s)"
else
    assert_fail_msg "large log still too slow: ${NEW_MS}ms"
fi

assert_eq "$(awk '$3=="198.51.100.200"{print $1,$2}' "$TMP/large-new.tsv")" "250 0" "large log: high-hit IP kept"
assert_eq "$(awk '$3=="198.51.100.201"{print $1,$2}' "$TMP/large-new.tsv")" "12 12" "large log: probe IP kept"
assert_eq "$(wc -l < "$TMP/large-new.tsv" | tr -d ' ')" "2" "large log: noise IPs omitted"

# Time a slice of the legacy algorithm to show why dry-run looked hung.
# Full 25k unique IPs would take minutes; 3k is enough to contrast.
SLICE_LOG="$TMP/slice-access.log"
python3 - "$SLICE_LOG" <<'PY'
import sys
path = sys.argv[1]
with open(path, "w", encoding="utf-8") as fh:
    for i in range(3000):
        a, b = divmod(i, 256)
        fh.write(
            f'172.64.0.1 203.1.{a}.{b} - - [22/Sep/2026:00:00:00 +0000] '
            f'"GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0" 123\n'
        )
    for _ in range(250):
        fh.write(
            '172.64.0.1 198.51.100.210 - - [22/Sep/2026:00:00:00 +0000] '
            '"GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0" 123\n'
        )
PY

echo "Timing legacy vs new on 3k unique IPs..."
START=$(date +%s%N)
count_candidates "$SLICE_LOG" "example.test" > "$TMP/slice-new.tsv"
END=$(date +%s%N)
SLICE_NEW_MS=$(( (END - START) / 1000000 ))
START=$(date +%s%N)
count_candidates_legacy "$SLICE_LOG" "example.test" > "$TMP/slice-old.tsv"
END=$(date +%s%N)
SLICE_OLD_MS=$(( (END - START) / 1000000 ))
echo "  new: ${SLICE_NEW_MS}ms   legacy: ${SLICE_OLD_MS}ms"

if cmp -s <(sort -k3,3 "$TMP/slice-new.tsv") <(sort -k3,3 "$TMP/slice-old.tsv"); then
    assert_ok "3k unique IPs: new matches legacy set"
else
    assert_fail_msg "3k unique IPs: new differs from legacy"
fi
if (( SLICE_NEW_MS < SLICE_OLD_MS )); then
    assert_ok "new counter faster than legacy (${SLICE_NEW_MS}ms < ${SLICE_OLD_MS}ms)"
else
    echo "WARN  new (${SLICE_NEW_MS}ms) not faster than legacy (${SLICE_OLD_MS}ms) on this host"
fi

# --- Jail decision helpers --------------------------------------------------

if iputil skip "127.0.0.1"; then assert_ok "skip loopback"; else assert_fail_msg "skip loopback"; fi
if iputil skip "10.1.2.3"; then assert_ok "skip RFC1918"; else assert_fail_msg "skip RFC1918"; fi
if iputil skip "100.64.1.1"; then assert_ok "skip CGNAT"; else assert_fail_msg "skip CGNAT"; fi
if iputil skip "162.158.1.1"; then assert_ok "skip Cloudflare edge"; else assert_fail_msg "skip Cloudflare edge"; fi
# Documentation/TEST-NET ranges are reserved and skipped; use a real public address.
if iputil skip "8.8.8.8"; then assert_fail_msg "public IP should not skip"; else assert_ok "public IP not skipped"; fi

echo "office 203.0.113.9" > "$ALLOW_FILE"
if iputil skip "203.0.113.9"; then assert_ok "skip allowlisted host"; else assert_fail_msg "skip allowlisted host"; fi
: > "$ALLOW_FILE"

got=$(decide_cidr "198.51.100.10" 80 "Data Center/Web Hosting/Transit" "US" || true)
assert_eq "$got" "198.51.100.0/24" "non-GB hosting score 80 -> /24"

got=$(decide_cidr "198.51.100.10" 60 "Fixed Line ISP" "US" || true)
assert_eq "$got" "198.51.100.10/32" "non-GB residential score 60 -> /32"

if got=$(decide_cidr "198.51.100.10" 40 "Fixed Line ISP" "US"); then
    assert_fail_msg "non-GB score 40 should not jail (got $got)"
else
    assert_ok "non-GB score 40 not jailed"
    assert_eq "$(skip_reason 40 "Fixed Line ISP" "US")" "score 40 < 50" "skip_reason for low score"
fi

got=$(decide_cidr "198.51.100.10" 80 "Data Center/Web Hosting/Transit" "GB" || true)
assert_eq "$got" "198.51.100.10/32" "GB hosting score 80 -> /32 only"

if got=$(decide_cidr "198.51.100.10" 90 "Fixed Line ISP" "GB"); then
    assert_fail_msg "GB residential should not jail (got $got)"
else
    assert_ok "GB residential not jailed"
    assert_eq "$(skip_reason 90 "Fixed Line ISP" "GB")" "GB residential/ISP (not jailed)" "skip_reason GB residential"
fi

if got=$(decide_cidr "198.51.100.10" 70 "Hosting" "GB"); then
    assert_fail_msg "GB hosting score 70 should not jail (got $got)"
else
    assert_ok "GB hosting score 70 not jailed"
    assert_eq "$(skip_reason 70 "Hosting" "GB")" "GB hosting score 70 < 75" "skip_reason GB hosting under threshold"
fi

echo
echo "Passed: $PASS   Failed: $FAIL"
if (( FAIL > 0 )); then
    exit 1
fi
