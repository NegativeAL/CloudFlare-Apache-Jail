# CloudFlare-Apache-Jail

Scan Apache access logs on an origin server and append abusive clients to a single Cloudflare IP list. Every zone that uses `ip.src in $jail_list` in a WAF custom rule (`BLOCK_BOTS`) then blocks those addresses at the edge.

Built for **Cloudflare Free**: one custom IP list (up to 10,000 items), no rewriting of rule expressions.

## How it decides

An IP is looked up on AbuseIPDB if it has many requests in the current log **or** enough hits on probe paths (`xmlrpc.php`, default `/wp-login.php`, `/wp-admin`, and optional extra paths).

| Signal | Action |
| --- | --- |
| Non-GB, score ≥ 50 | Jail that address (`/32` or `/128`) |
| Non-GB, hosting/datacentre, score ≥ 75 | Optional `/24` or IPv6 `/64` |
| GB hosting, score ≥ 75 | Jail `/32` only |
| GB residential / mobile | Leave alone |

Private, loopback, Cloudflare edge, and `/etc/cloudflare-jail.allow` addresses are never queued.

## Repo layout

| File | Purpose |
| --- | --- |
| `cloudflare-jail.sh` | Cron job on the Apache host |
| `cloudflare-jail.env.example` | Template for `/etc/cloudflare-jail.env` |
| `expression-to-jail-csv.py` | One-time converter: old `BLOCK_BOTS` expression → IP list CSV |

Do not commit API keys, `jail_list.csv`, or `block_bots.txt`.

## Install (short)

1. Rotate any keys that were previously stored in a script.
2. Create an account IP list named `jail_list`. Upload existing `BLOCK_BOTS` CIDRs via CSV if you are migrating.
3. On each zone, set `BLOCK_BOTS` to `ip.src in $jail_list`.
4. On the Apache host: copy the script to `/usr/local/sbin/cloudflare-jail.sh`, copy the env example to `/etc/cloudflare-jail.env` (`0600`), fill in AbuseIPDB key, Cloudflare token (`Account Filter Lists: Edit`), and Account ID.
5. `sudo /usr/local/sbin/cloudflare-jail.sh --dry-run` then enable cron.

Optional host-only files:

- `/etc/cloudflare-jail.allow` — never-jail IPs/CIDRs
- `/etc/cloudflare-jail.paths` — extra probe paths (including a renamed login URL)

## Token and IDs

- **CLOUDFLARE_API_TOKEN** — secret. Permission: Account → Account Filter Lists → Edit.
- **CLOUDFLARE_ACCOUNT_ID** — 32-character hex on any zone Overview sidebar. Same for all zones on one account.
- **CLOUDFLARE_LIST_NAME** — `jail_list` (must match `$jail_list` in the WAF rule).
