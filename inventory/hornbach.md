# HORNBACH Holding AG & Co. KGaA / HORNBACH Group inventory (discovery seed 2026-09-02)
# NOTE: hosts below are discovery candidates from passive DNS/CT; confirm in-scope vs program scope before active testing.
auth.hornbach.com
hornbach.com
login.hornbach.com
www.hornbach.com

## PASSIVE RECON 2026-09-02 (read-only, non-intrusive)

> Recon observations only. These are NOT confirmed vulnerabilities; ownership/in-scope of each host must be confirmed against the program scope before any active testing. Hosts resolve + serve HTTP — investigation requires scoped authorization.

**Probed:** 4 hosts | **Live HTTP:** 2

| Host | Status | Server/Tech |
|---|---|---|
| `auth.hornbach.com` | 302 | Server: cloudflare; X-Powered-By: cidaas -> https://hornbach.de/ |
| `login.hornbach.com` | 302 | Server: Varnish -> https://www.hornbach.de/customer |

**CNAME review signals (2):**
- `auth.hornbach.com` -> `hornbach-prod.cidaas.eu`
- `login.hornbach.com` -> `n.sni.global.fastly.net`

**Takeover-review flags (1):** (DNS-level, most resolve = claimed/live, verify ownership)
- `login.hornbach.com` :: CNAME-TO-Fastly :: CNAME->n.sni.global.fastly.net, resolves to ['199.232.105.91'], verify ownership

## DEEP SERVICE SCAN 2026-09-02 (read-only connect+banner)
**Host:** `auth.hornbach.com` | **Ports:** [21, 22, 23, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1080, 1433, 1521, 2082, 2083, 2086, 2087, 3306, 3389, 5432, 5900, 6379, 7001, 7070, 8000, 8008, 8009, 8080, 8081, 8082, 8083, 8088, 8090, 8161, 8443, 8800, 8888, 9000, 9090, 9200, 9300, 9999, 10000, 10051, 11211, 27017, 50070, 50075]
**Non-web ports observed:** [21, 22, 23, 53, 110, 143, 465, 587, 993, 995, 1080, 1433, 1521, 2082, 2083, 2086, 2087, 3306, 3389, 5432, 5900, 6379, 7001, 7070, 8000, 8008, 8009, 8080, 8081, 8082, 8083, 8088, 8090, 8161, 8443, 8800, 8888, 9000, 9090, 9200, 9300, 9999, 10000, 10051, 11211, 27017, 50070, 50075]
> NOTE: repeated identical non-web port sets (e.g. 2082,2083,2086,2087,8080,8443) across many hosts and wide port sets are likely a shared edge/proxy answering EOF, NOT confirmed real services. Verify with a proper port scanner (e.g. nmap) under authorization before treating as real. These are surface-map hints only, not findings.

## DEEP SERVICE SCAN 2026-09-02 (read-only connect+banner)
**Host:** `login.hornbach.com` | **Ports:** [80, 443]
**Web surface only:** [80, 443]
