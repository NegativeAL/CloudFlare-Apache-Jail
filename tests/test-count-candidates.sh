#!/bin/bash
# Exercise count_candidates and jail-decision helpers without APIs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/cloudflare-jail.sh"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
LOG="$TMP/access.log"
ALLOW_FILE="$TMP/allow"
: > "$ALLOW_FILE"

HIT_THRESHOLD=250
PROBE_THRESHOLD=10
fail=0

expect() {
    local ip="$1" want_hits="$2" want_probes="$3"
    if [[ "${hits[$ip]:-}" != "$want_hits" || "${probes[$ip]:-}" != "$want_probes" ]]; then
        echo "FAIL $ip: got hits=${hits[$ip]:-missing} probes=${probes[$ip]:-missing} want ${want_hits}/${want_probes}" >&2
        fail=1
    fi
}
expect_absent() {
    local ip="$1"
    if [[ -n "${hits[$ip]:-}" ]]; then
        echo "FAIL $ip: should not be a candidate (hits=${hits[$ip]} probes=${probes[$ip]})" >&2
        fail=1
    fi
}
assert_eq() {
    local got="$1" want="$2" msg="$3"
    if [[ "$got" != "$want" ]]; then
        echo "FAIL $msg (got '$got' want '$want')" >&2
        fail=1
    fi
}

python3 - "$LOG" <<'PY'
import sys
from datetime import datetime, timezone

path = sys.argv[1]
now = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
edge = "108.162.192.1"

def line(ip, uri, n=1):
    row = (
        f'{edge} {ip} - - [{now}] "GET {uri} HTTP/1.1" 404 12 '
        f'"-" "Mozilla/5.0" 100\n'
    )
    return row * n

with open(path, "w", encoding="utf-8") as fh:
    # Unique IPs well below both thresholds — this is what made the old
    # bash/awk-per-IP loop look hung.
    for i in range(25000):
        fh.write(line(f"203.0.{i // 256}.{i % 256}", "/"))
    fh.write(line("1.2.3.4", "/", 300))
    fh.write(line("5.6.7.8", "/xmlrpc.php", 12))
    fh.write(line("9.9.9.9", "/", 200))
    fh.write(line("8.8.8.8", "/wp-login.php", 9))
    fh.write(line("2001:db8::1", "/.env", 11))
PY

start=$(date +%s%N)
mapfile -t rows < <(count_candidates "$LOG" "example.com")
elapsed_ms=$(( ( $(date +%s%N) - start ) / 1000000 ))

declare -A hits probes
for row in "${rows[@]}"; do
    IFS=$'\t' read -r h p ip <<< "$row"
    hits["$ip"]="$h"
    probes["$ip"]="$p"
done

expect "1.2.3.4" 300 0
expect "5.6.7.8" 12 12
expect "2001:db8::1" 11 11
expect_absent "9.9.9.9"
expect_absent "8.8.8.8"
expect_absent "203.0.0.1"

if (( ${#rows[@]} != 3 )); then
    echo "FAIL expected 3 candidates, got ${#rows[@]}" >&2
    printf '  %s\n' "${rows[@]}" >&2
    fail=1
fi

# Highest hit count should be first.
IFS=$'\t' read -r first_hits _ first_ip <<< "${rows[0]}"
if [[ "$first_hits" != "300" || "$first_ip" != "1.2.3.4" ]]; then
    echo "FAIL expected 1.2.3.4 first by hits, got hits=$first_hits ip=$first_ip" >&2
    fail=1
fi

# 25k unique IPs must finish in well under the old multi-minute hang.
if (( elapsed_ms > 15000 )); then
    echo "FAIL count_candidates took ${elapsed_ms}ms (want < 15000ms)" >&2
    fail=1
fi

# Dry-run style ( ... ) | tee must print progress before IP lines.
CANDIDATES_FILE="$TMP/candidates.tsv"
EMAIL_BODY="$TMP/email.body"
(
    echo "Domain: example.com"
    echo "   Scanning log for candidates (hits>=${HIT_THRESHOLD} or probes>=${PROBE_THRESHOLD})..."
    count_candidates "$LOG" "example.com" > "$CANDIDATES_FILE"
    echo "   Candidates: $(wc -l < "$CANDIDATES_FILE" | tr -d ' ')"
    while IFS=$'\t' read -r h p ip; do
        echo "   IP $ip  hits=$h  probes=$p"
    done < "$CANDIDATES_FILE"
) | tee "$EMAIL_BODY" >/dev/null

if ! grep -q "Scanning log for candidates" "$EMAIL_BODY" \
    || ! grep -q "Candidates: 3" "$EMAIL_BODY" \
    || ! grep -q "IP 1.2.3.4" "$EMAIL_BODY"; then
    echo "FAIL dry-run tee pipeline missing expected output" >&2
    cat "$EMAIL_BODY" >&2
    fail=1
fi

# Empty probe-pattern list still filters on total hits only.
saved_patterns=("${PROBE_PATTERNS[@]}")
PROBE_PATTERNS=()
mapfile -t no_probe_rows < <(count_candidates "$LOG" "example.com")
PROBE_PATTERNS=("${saved_patterns[@]}")
declare -A np_hits
for row in "${no_probe_rows[@]}"; do
    IFS=$'\t' read -r h p ip <<< "$row"
    np_hits["$ip"]="$h"
done
if [[ -n "${np_hits[5.6.7.8]:-}" ]]; then
    echo "FAIL probe-only IP should be omitted when PROBE_PATTERNS is empty" >&2
    fail=1
fi
if [[ "${np_hits[1.2.3.4]:-}" != "300" ]]; then
    echo "FAIL high-hit IP missing with empty PROBE_PATTERNS" >&2
    fail=1
fi

# skip / jail helpers — same decision table as production.
if ! iputil skip "127.0.0.1"; then echo "FAIL skip loopback" >&2; fail=1; fi
if ! iputil skip "10.1.2.3"; then echo "FAIL skip RFC1918" >&2; fail=1; fi
if ! iputil skip "100.64.1.1"; then echo "FAIL skip CGNAT" >&2; fail=1; fi
if ! iputil skip "162.158.1.1"; then echo "FAIL skip Cloudflare edge" >&2; fail=1; fi
if iputil skip "8.8.8.8"; then echo "FAIL public IP should not skip" >&2; fail=1; fi
echo "203.0.113.9" > "$ALLOW_FILE"
if ! iputil skip "203.0.113.9"; then echo "FAIL skip allowlisted host" >&2; fail=1; fi
: > "$ALLOW_FILE"

assert_eq "$(decide_cidr "1.2.3.4" 80 "Data Center/Web Hosting/Transit" "US" || true)" "1.2.3.0/24" "non-GB hosting score 80 -> /24"
assert_eq "$(decide_cidr "1.2.3.4" 60 "Fixed Line ISP" "US" || true)" "1.2.3.4/32" "non-GB residential score 60 -> /32"
if decide_cidr "1.2.3.4" 40 "Fixed Line ISP" "US" >/dev/null; then
    echo "FAIL non-GB score 40 should not jail" >&2
    fail=1
else
    assert_eq "$(skip_reason 40 "Fixed Line ISP" "US")" "score 40 < 50" "skip_reason low score"
fi
assert_eq "$(decide_cidr "1.2.3.4" 80 "Data Center/Web Hosting/Transit" "GB" || true)" "1.2.3.4/32" "GB hosting score 80 -> /32"
if decide_cidr "1.2.3.4" 90 "Fixed Line ISP" "GB" >/dev/null; then
    echo "FAIL GB residential should not jail" >&2
    fail=1
else
    assert_eq "$(skip_reason 90 "Fixed Line ISP" "GB")" "GB residential/ISP (not jailed)" "skip_reason GB residential"
fi
if decide_cidr "1.2.3.4" 70 "Hosting" "GB" >/dev/null; then
    echo "FAIL GB hosting score 70 should not jail" >&2
    fail=1
else
    assert_eq "$(skip_reason 70 "Hosting" "GB")" "GB hosting score 70 < 75" "skip_reason GB hosting under threshold"
fi

if (( fail )); then
    echo "count_candidates tests failed in ${elapsed_ms}ms" >&2
    exit 1
fi

echo "count_candidates: ${#rows[@]} candidates in ${elapsed_ms}ms"
echo "helpers: skip/jail decisions ok"
