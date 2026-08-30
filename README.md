# CloudFlare-Apache-Jail

Scan Apache access logs on your origin and append abusive client addresses to one Cloudflare IP list. A WAF custom rule on each zone then blocks those addresses at the edge.

Works on **Cloudflare Free**: one custom IP list (up to 10,000 items) and a short static rule. The script never rewrites the rule expression.

## What you need

- Apache (httpd) behind Cloudflare, with the **real visitor IP** in log field 2
- `curl`, `jq`, `python3`, and `flock` on the origin
- An [AbuseIPDB](https://www.abuseipdb.com/) API key
- A Cloudflare **API Token** (not a Global API Key)

Recommended Apache format (field 1 is the Cloudflare edge, field 2 is the visitor after `mod_remoteip`):

```apache
LogFormat "%{c}a %h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\" %D" cloudflare
```

If your visitor IP is not field 2, change `parse_log` in the script before you run it.

## 1. Cloudflare

### Create the IP list

1. Dashboard → **Manage Account** → **Configurations** → **Lists**
2. **Create** an **IP** list named exactly `jail_list`
3. Free plans allow **one** custom list. Use that slot for this list.

### Create the WAF rule

On **each** zone you want protected:

1. **Security** → **WAF** → **Custom rules**
2. Add a rule (name it what you like, e.g. `BLOCK_BOTS`)
3. Expression:

```txt
ip.src in $jail_list
```

4. Action: **Block**

The same list is shared across every zone on the account. Abuse found on one site is blocked on all of them.

### Create the API token

**My Profile** → **API Tokens** → **Create Token** → **Create Custom Token**:

| Scope | Resource | Access |
| --- | --- | --- |
| Account | Account Filter Lists | Edit |

Account Resources: include the account that owns your zones.

Copy the token once. Find **Account ID** on any zone **Overview** page (right sidebar, 32 hex characters). It is not the Zone ID.

## 2. Origin server

```bash
sudo install -m 700 cloudflare-jail.sh /usr/local/sbin/cloudflare-jail.sh
sudo install -m 600 cloudflare-jail.env.example /etc/cloudflare-jail.env
sudo ${EDITOR:-nano} /etc/cloudflare-jail.env
```

If you copy files from Windows, run `sudo sed -i 's/\r$//' /usr/local/sbin/cloudflare-jail.sh /etc/cloudflare-jail.env`.

Set at least:

```bash
ABUSEIPDB_API_KEY=
CLOUDFLARE_API_TOKEN=
CLOUDFLARE_ACCOUNT_ID=
CLOUDFLARE_LIST_NAME=jail_list
```

Edit `DOMAIN_MATRIX` in `cloudflare-jail.sh` so each log path maps to a hostname:

```bash
declare -A DOMAIN_MATRIX
DOMAIN_MATRIX=(
    ["/var/log/httpd/example.com-access.log"]="example.com"
)
```

Optional host-only files (mode `0600`):

| File | Purpose |
| --- | --- |
| `/etc/cloudflare-jail.allow` | IPs/CIDRs that must never be jailed (office, origin, monitors) |
| `/etc/cloudflare-jail.paths` | Extra probe URL fragments (for example a renamed login path) |

## 3. Test, then schedule

```bash
sudo /usr/local/sbin/cloudflare-jail.sh --init-list
sudo /usr/local/sbin/cloudflare-jail.sh --dry-run
sudo /usr/local/sbin/cloudflare-jail.sh --dry-run -t example.com
```

`--init-list` is a no-op if `jail_list` already exists. `--dry-run` looks up AbuseIPDB and prints what would be added; it does not change the list.

When a dry-run looks right:

```bash
sudo /usr/local/sbin/cloudflare-jail.sh
```

Then open a site and an admin URL to confirm you are not locked out.

Cron (once a day is enough):

```bash
echo '30 3 * * * root /usr/local/sbin/cloudflare-jail.sh' | sudo tee /etc/cron.d/cloudflare-jail
```

## How it decides

An address is looked up on AbuseIPDB if it has many requests in the current log (default 250) **or** enough hits on probe paths (default 10). Built-in probes include `/xmlrpc.php`, `/wp-login.php`, `/wp-admin`, `/.env`, and similar.

| Signal | Action |
| --- | --- |
| Non-GB, score ≥ 50 | Jail that address (`/32` or `/128`) |
| Non-GB, hosting/datacentre, score ≥ 75 | `/24` or IPv6 `/64` |
| GB hosting, score ≥ 75 | `/32` only |
| GB residential / mobile | Leave alone |

Private, loopback, link-local, CGNAT, Cloudflare edge IPv4, and allowlisted addresses are skipped.

Thresholds can be overridden in `/etc/cloudflare-jail.env`: `HIT_THRESHOLD`, `PROBE_THRESHOLD`, `SCORE_JAIL`, `SCORE_SUBNET`, `SCORE_GB_HOSTING`.

## Token errors

`Authentication error` (code 10000) means the token string was rejected. Typical causes:

- Global API Key used instead of an API Token
- Token missing **Account Filter Lists: Edit**
- Token not scoped to this account
- `CLOUDFLARE_ACCOUNT_ID` is a Zone ID
- Windows `CRLF` in `/etc/cloudflare-jail.env`

Check without printing the secret:

```bash
sudo bash -c 'source /etc/cloudflare-jail.env
curl -sS https://api.cloudflare.com/client/v4/user/tokens/verify \
  -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}"'
```

You want `"success": true` and `"status": "active"`.

## Files

| File | Purpose |
| --- | --- |
| `cloudflare-jail.sh` | Install on the origin; run from cron |
| `cloudflare-jail.env.example` | Template for `/etc/cloudflare-jail.env` |
| `expression-to-jail-csv.py` | Optional: turn an existing `ip.src in { … }` expression into a list CSV |

Do not commit real env files or live jail CSVs.
