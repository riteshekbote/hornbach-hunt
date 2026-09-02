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
