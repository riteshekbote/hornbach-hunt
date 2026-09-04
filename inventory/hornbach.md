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

## 2026-09-02 21:46:10 UTC

## 2026-09-02 23:55:43 UTC

## 2026-09-03 03:44:54 UTC

## 2026-09-03 08:47:26 UTC

## 2026-09-03 13:26:05 UTC

## 2026-09-03 17:21:30 UTC

## 2026-09-03 20:03:14 UTC
- NEW auth.hornbach.com: OAuth authorize endpoint returns HTTP 404 (not 302) for test client_ids — suggests endpoint path may differ or requires valid registered client_id
- NEW auth.hornbach.com: Root path (/) now returns HTTP 200 len=3038 (was 302 in inventory) — likely serves cidaas login UI directly
- NEW login.hornbach.com: Root path (/) returns HTTP 200 len=3038 (was 302 in inventory) — serves content directly, not redirecting to hornbach.de
- CHANGED Both auth.hornbach.com and login.hornbach.com return identical content length (3038) — possible shared error page or same backend response
- CHANGED auth.hornbach.com: OIDC discovery endpoint `.well-known/openid-configuration` returns 200 with full provider metadata; 6 new service endpoints discovered (authz-srv, token-srv, users-srv, apps-srv, us
- CHANGED auth.hornbach.com: Authorization endpoint `authz-srv/authz` confirmed live — returns 302 to error page with `invalid_client` + verbose error_description + error_hint
- CHANGED auth.hornbach.com: Device code flow endpoint `authz-srv/device/authz` confirmed live — returns 400 with JSON `invalid_request`
- CHANGED auth.hornbach.com: JWKS endpoint `.well-known/jwks.json` returns 5+ RSA public keys (RS256)
- NEW auth.hornbach.com: Client registration endpoint `apps-srv/clients/register` exists in OIDC metadata — returns 404 on GET, may accept POST (unauthenticated client registration potential)
- NEW auth.hornbach.com: SCIM endpoint `user-scim-srv/v2` exists in OIDC metadata — returns 404 on GET, worth POST/fuzzing (user provisioning protocol)
- NEW auth.hornbach.com: Introspection endpoint `token-srv/introspect` exposed in metadata
- CHANGED www.hornbach.com / hornbach.de: Login page returns bot-challenge page (FingerprintJS-based `_fs_ch_st_` cookie), 3038-byte stub, not direct login form

## 2026-09-03 22:31:53 UTC
- NEW auth.hornbach.com: OAuth authorize endpoint `/oauth2/authorize` returns HTTP 404 for guessed client_ids — endpoint path differs or requires valid registered client_id
- NEW auth.hornbach.com: Root path (/) returns HTTP 200 len=3038 (was 302) — serves cidaas login UI directly
- NEW login.hornbach.com: Root path (/) returns HTTP 200 len=3038 (was 302) — serves content directly, not redirecting to hornbach.de
- CHANGED Both auth.hornbach.com and login.hornbach.com return identical content length (3038) — possible shared error/maintenance page
- CHANGED auth.hornbach.com: OIDC discovery `.well-known/openid-configuration` returns 200 with full provider metadata; 6 service endpoints discovered (authz-srv, token-srv, users-srv, apps-srv, user-scim-srv, 
- CHANGED auth.hornbach.com: Authorization endpoint `authz-srv/authz` confirmed live — returns 302 to error page with `invalid_client` + verbose error_description + error_hint
- CHANGED auth.hornbach.com: Device code flow endpoint `authz-srv/device/authz` confirmed live — returns 400 JSON `invalid_request`
- CHANGED auth.hornbach.com: JWKS `.well-known/jwks.json` returns 5+ RSA public keys (RS256)
- NEW auth.hornbach.com: Client registration endpoint `apps-srv/clients/register` in OIDC metadata — returns 404 on GET, may accept POST (unauthenticated registration potential)
- NEW auth.hornbach.com: SCIM endpoint `user-scim-srv/v2` in metadata — returns 404 on GET, worth POST/fuzzing
- NEW auth.hornbach.com: Introspection endpoint `token-srv/introspect` exposed in metadata
- CHANGED www.hornbach.com / hornbach.de: Login page returns bot-challenge page (FingerprintJS `_fs_ch_st_` cookie), 3038-byte stub

## 2026-09-04 00:43:49 UTC

## 2026-09-04 05:17:56 UTC

## 2026-09-04 09:58:02 UTC

## 2026-09-04 14:20:23 UTC
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" without client auth — RFC 7009 violation; second unauthenticated token management endpoint alongside introspection
- NEW auth.hornbach.com/login-srv/social/token: GET returns HTTP 500 with empty error JSON + `Access-Control-Allow-Origin: *`
- CHANGED auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053 "par is not enabled for this tenant")
- CHANGED api.hornbach.de: POST root returns 404 JSON with X-CorrelationID — consistent SAP APIM, no new routes

## 2026-09-04 17:49:13 UTC
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" without client auth — RFC 7009 violation (second unauthenticated token mgmt endpoint)
- NEW auth.hornbach.com/login-srv/social/token: GET returns HTTP 500 with empty error JSON + Access-Control-Allow-Origin: *
- CHANGED auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- CHANGED auth.hornbach.com/token-srv/introspect: now returns HTTP 404 (was accessible unauthenticated, RFC 7662 compliant returning active=false)
- CHANGED api.hornbach.de: POST root returns 404 JSON with X-CorrelationID — consistent SAP APIM, no new routes discovered
- CHANGED hornbach.com: no wildcard DNS confirmed (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 known scoped hosts resolve

## 2026-09-04 20:01:29 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 {"active":false} unauthenticated — endpoint RE-CONFIRMED live (transient 404 in prior run was edge/routing, not permanent)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" unauthenticated — endpoint re-confirmed live; both token management endpoints stable unauthenticated
- NEW auth.hornbach.com/.well-known/status: returns HTTP 200 {"status":"OK","updatedAt"} — discovery property status endpoint live (per OIDC metadata)
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=public now returns 302 to /identity/error?error=invalid_client&error_code=AUTH10007 — confirms uniform invalid_client gate; previous 404 vs 302 variance is
- NEW auth.hornbach.com/token-srv/revoke: now returns HTTP 404 (was 200 OK without client auth per 2026-09-04 14:20 lead) — endpoint appears remediated or blocked
- NEW auth.hornbach.com/authz-srv/authz: returns HTTP 200 with valid client_id=<found> (probe 2026-09-04 14:20/17:49) — authorization endpoint responds to valid client, not just invalid_client errors
- CHANGED auth.hornbach.com/token-srv/introspect: confirmed HTTP 404 (was accessible unauthenticated returning active=false)
- CHANGED hornbach.com: no wildcard DNS confirmed — only 4 scoped hosts resolve
- CHANGED api.hornbach.de: POST root returns 404 JSON with X-CorrelationID — consistent SAP APIM, no new routes
