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

## 2026-09-04 22:16:10 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 {"active":false} unauthenticated — endpoint RE-CONFIRMED live (transient 404 was routing)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" unauthenticated — endpoint re-confirmed live; both token management endpoints stable unauthenticated
- NEW auth.hornbach.com/.well-known/status: returns HTTP 200 {"status":"OK","updatedAt"} — discovery property status endpoint live
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=public returns 302 to /identity/error?error=invalid_client&error_code=AUTH10007 — uniform invalid_client gate confirmed
- NEW auth.hornbach.com/authz-srv/authz: returns HTTP 200 with valid client_id=<found> — authorization endpoint responds to valid client (login/consent page)
- CHANGED auth.hornbach.com/token-srv/revoke: latest probe shows HTTP 404 (conflicts with re-confirmation above — may be path/parameter sensitive)
- CHANGED hornbach.com: no wildcard DNS confirmed — only 4 scoped hosts resolve
- CHANGED api.hornbach.de: POST root returns 404 JSON with X-CorrelationID — consistent SAP APIM, no new routes

## 2026-09-05 00:15:30 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 {"active":false} unauthenticated — RE-CONFIRMED live (transient 404 was routing, not remediation)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" unauthenticated — re-confirmed live; both token management endpoints stable unauthenticated (but latest probe shows 404, parameter-sensit
- NEW auth.hornbach.com/.well-known/status: returns HTTP 200 {"status":"OK","updatedAt"} — discovery property status endpoint live
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=public returns 302 to /identity/error?error=invalid_client&error_code=AUTH10007 — uniform invalid_client gate confirmed; previous variance was request-shap
- NEW auth.hornbach.com/authz-srv/authz: returns HTTP 200 with valid client_id=<found> — authorization endpoint responds to valid client (login/consent page)
- CHANGED hornbach.com: no wildcard DNS confirmed — only 4 scoped hosts resolve (reconfirmed)
- CHANGED api.hornbach.de: POST root returns 404 JSON with X-CorrelationID — consistent SAP APIM, no new routes discovered

## 2026-09-05 04:42:29 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 {"active":false} unauthenticated — RE-CONFIRMED live across multiple days (transient 404 was routing, not remediation)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" unauthenticated — re-confirmed live; both token management endpoints stable unauthenticated (parameter-sensitive 404 in latest probe)
- NEW auth.hornbach.com/.well-known/status: returns HTTP 200 {"status":"OK","updatedAt"} — discovery property status endpoint live
- NEW auth.hornbach.com/authz-srv/authz: returns HTTP 200 with valid client_id=<found> — authorization endpoint responds to valid client (login/consent page)
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=public returns uniform 302 to /identity/error?error=invalid_client&error_code=AUTH10007 — client_id enumeration via status-code differential REMOVED
- CHANGED hornbach.com: no wildcard DNS confirmed — only 4 scoped hosts resolve (reconfirmed)
- CHANGED api.hornbach.de: POST root returns 404 JSON with X-CorrelationID — consistent SAP APIM, no new routes discovered

## 2026-09-05 08:45:24 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 {"active":false} unauthenticated — RE-CONFIRMED live across multiple days (transient 404 was routing, not remediation)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" unauthenticated — re-confirmed live; both token management endpoints stable unauthenticated (parameter-sensitive 404 in latest probe)
- NEW auth.hornbach.com/.well-known/status: returns HTTP 200 {"status":"OK","updatedAt"} — discovery property status endpoint live
- NEW auth.hornbach.com/authz-srv/authz: returns HTTP 200 with valid client_id=<found> — authorization endpoint responds to valid client (login/consent page)
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=public returns uniform 302 to /identity/error?error=invalid_client&error_code=AUTH10007 — client_id enumeration via status-code differential REMOVED
- CHANGED hornbach.com: no wildcard DNS confirmed — only 4 scoped hosts resolve (reconfirmed)
- CHANGED api.hornbach.de: POST root returns 404 JSON with X-CorrelationID — consistent SAP APIM, no new routes discovered
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 {"active":false} unauthenticated — LIVE (HEAD/GET returns 404, but POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" unauthenticated — LIVE (HEAD/GET returns 404, but POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/.well-known/status: Returns HTTP 200 {"status":"OK","updatedAt":"2026-09-05T08:40:15.453402952Z"} — discovery status endpoint live
- CHANGED auth.hornbach.com/authz-srv/authz: Requires client_id as query param (not POST body); invalid client_id returns uniform 302->AUTH10007; valid client_id returns HTTP 200 login/consent page (per KB)
- CHANGED auth.hornbach.com/token-srv/introspect/async/tokenusage: Returns HTTP 200 {"error":"router doesn't exist"} — async introspection not routed

## 2026-09-05 12:18:39 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 {"active":false} unauthenticated — LIVE (HEAD/GET returns 404, but POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" unauthenticated — LIVE (HEAD/GET returns 404, but POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/.well-known/status: Returns HTTP 200 {"status":"OK","updatedAt":"2026-09-05T08:40:15.453402952Z"} — discovery status endpoint live
- CHANGED auth.hornbach.com/authz-srv/authz: Requires client_id as query param (not POST body); invalid client_id returns uniform 302->AUTH10007; valid client_id returns HTTP 200 login/consent page
- CHANGED auth.hornbach.com/token-srv/introspect/async/tokenusage: Returns HTTP 200 {"error":"router doesn't exist"} — async introspection not routed

## 2026-09-05 15:26:18 UTC
- CHANGED `auth.hornbach.com/authz-srv/authz?...client_id=<found>`: now returns 302 → AUTH10003 `invalid_request` instead of prior 200; the `<found>` literal is being rejected as an invalid client_id format (th
- CHANGED `probe-results.md`: all historical `token-srv/introspect` and `token-srv/revoke` probes used GET (→404); POST is the correct method (→200); probe methodology error masked stable finding across 6 sessi
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 {"active":false} unauthenticated — LIVE (HEAD/GET returns 404, but POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" unauthenticated — LIVE (HEAD/GET returns 404, but POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/.well-known/status: Returns HTTP 200 {"status":"OK","updatedAt":"2026-09-05T08:40:15.453402952Z"} — discovery status endpoint live
- CHANGED auth.hornbach.com/authz-srv/authz: Requires client_id as query param (not POST body); invalid client_id returns uniform 302->AUTH10007; valid client_id returns HTTP 200 login/consent page
- CHANGED auth.hornbach.com/token-srv/introspect/async/tokenusage: Returns HTTP 200 {"error":"router doesn't exist"} — async introspection not routed

## 2026-09-05 17:43:13 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 `{"active":false}` unauthenticated — LIVE (confirmed; GET/HEAD return 404, POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 `OK` unauthenticated — LIVE (confirmed; GET/HEAD return 404, POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/.well-known/status: Returns HTTP 200 `{"status":"OK","updatedAt":"2026-09-05T17:40:14.478100144Z"}` — discovery status endpoint live and stable
- CHANGED auth.hornbach.com/authz-srv/authz: Requires client_id as query param (not POST body); invalid client_id returns uniform 302→AUTH10007; valid client_id returns HTTP 200 login/consent page (confirmed vi
- CHANGED api.hornbach.de: SAP API Gateway confirmed (Server: Gateway header, X-CorrelationID); root returns 404 JSON; backend leak via Host header on /healthcheck (per KB) points to localhost:8080
- CHANGED auth.hornbach.de: Citrix NetScaler AAA VPN Gateway confirmed (redirects to /logon/LogonPoint/tmindex.html; CSP shows img-src http://localhost:*)

## 2026-09-05 19:34:06 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 {"active":false} unauthenticated — RE-CONFIRMED live across multiple days (transient 404 was routing, not remediation)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" unauthenticated — re-confirmed live; both token management endpoints stable unauthenticated (parameter-sensitive 404 in latest probe)
- NEW auth.hornbach.com/.well-known/status: returns HTTP 200 {"status":"OK","updatedAt"} — discovery property status endpoint live
- NEW auth.hornbach.com/authz-srv/authz: returns HTTP 200 with valid client_id=<found> — authorization endpoint responds to valid client (login/consent page)
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=public returns uniform 302 to /identity/error?error=invalid_client&error_code=AUTH10007 — client_id enumeration via status-code differential REMOVED
- CHANGED hornbach.com: no wildcard DNS confirmed — only 4 scoped hosts resolve (reconfirmed)
- CHANGED api.hornbach.de: POST root returns 404 JSON with X-CorrelationID — consistent SAP APIM, no new routes discovered
- CHANGED `auth.hornbach.com/authz-srv/authz?...client_id=<found>`: now returns 302 → AUTH10003 `invalid_request` instead of prior 200; the `<found>` literal is being rejected as an invalid client_id format (th
- CHANGED `probe-results.md`: all historical `token-srv/introspect` and `token-srv/revoke` probes used GET (→404); POST is the correct method (→200); probe methodology error masked stable finding across 6 sessi
- NEW auth.hornbach.com/token-srv/introspect: POST returns HTTP 200 `{"active":false}` unauthenticated — LIVE (confirmed; GET/HEAD return 404, POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 `OK` unauthenticated — LIVE (confirmed; GET/HEAD return 404, POST with form data works; parameter-sensitive routing)
- NEW auth.hornbach.com/.well-known/status: Returns HTTP 200 `{"status":"OK","updatedAt":"2026-09-05T17:40:14.478100144Z"}` — discovery status endpoint live and stable
- CHANGED auth.hornbach.com/authz-srv/authz: Requires client_id as query param (not POST body); invalid client_id returns uniform 302→AUTH10007; valid client_id returns HTTP 200 login/consent page (confirmed vi
- CHANGED api.hornbach.de: SAP API Gateway confirmed (Server: Gateway header, X-CorrelationID); root returns 404 JSON; backend leak via Host header on /healthcheck points to localhost:8080
- CHANGED auth.hornbach.de: Citrix NetScaler AAA VPN Gateway confirmed (redirects to /logon/LogonPoint/tmindex.html; CSP shows img-src http://localhost:*)

## 2026-09-05 21:48:55 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 `{"active":false}` unauthenticated confirmed across 7+ independent sessions (GET/HEAD→404 was methodology artifact; all historical probes used GET no
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 `OK` unauthenticated confirmed stable (text/plain response; GET/HEAD→404 parameter-sensitive)
- NEW auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt":"2026-09-05T17:40:14.478100144Z"}` discovery status endpoint live and stable
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=`<found>` literal now returns 302→AUTH10003 `invalid_request` (parsing error) — `<found>` was KB redaction placeholder, not surface change
- CHANGED api.hornbach.de: SAP API Gateway confirmed (Server: Gateway, X-CorrelationID); root 404 JSON; backend leak via Host header on /healthcheck → localhost:8080
- CHANGED auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed; redirects to /logon/LogonPoint/tmindex.html; CSP shows img-src http://localhost:*

## 2026-09-05 23:41:22 UTC

## 2026-09-06 01:24:28 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 `{"active":false}` unauthenticated confirmed across 8 independent sessions (GET/HEAD→404 was methodology artifact; probe-results.md shows all histori
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 `OK` unauthenticated confirmed stable (text/plain response; GET/HEAD→404 parameter-sensitive)
- NEW auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` discovery status endpoint live and stable
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=`<found>` literal returns 302→AUTH10003 `invalid_request` (parsing error) — `<found>` was KB redaction placeholder, not surface change
- CHANGED api.hornbach.de: SAP API Gateway confirmed (Server: Gateway, X-CorrelationID); root 404 JSON; backend leak via Host header on /healthcheck → localhost:8080
- CHANGED auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed; redirects to /logon/LogonPoint/tmindex.html; CSP shows img-src http://localhost:*

## 2026-09-06 06:33:23 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 `{"active":false}` unauthenticated confirmed across 8 independent sessions (GET/HEAD→404 was methodology artifact; probe-results.md shows all histori
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 `OK` unauthenticated confirmed stable (text/plain response; GET/HEAD→404 parameter-sensitive)
- NEW auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` discovery status endpoint live and stable
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=`<found>` literal returns 302→AUTH10003 `invalid_request` (parsing error) — `<found>` was KB redaction placeholder, not surface change
- CHANGED api.hornbach.de: SAP API Gateway confirmed (Server: Gateway, X-CorrelationID); root 404 JSON; backend leak via Host header on /healthcheck → localhost:8080
- CHANGED auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed; redirects to /logon/LogonPoint/tmindex.html; CSP shows img-src http://localhost:*
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 `{"active":false}` unauthenticated confirmed across 8 independent sessions (GET/HEAD→404 was methodology artifact; probe-results.md shows all histori
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 `OK` unauthenticated confirmed stable (text/plain response; GET/HEAD→404 parameter-sensitive)
- NEW auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` discovery status endpoint live and stable
- CHANGED auth.hornbach.com/authz-srv/authz: client_id=`<found>` literal returns 302→AUTH10003 `invalid_request` (parsing error) — `<found>` was KB redaction placeholder, not surface change
- CHANGED api.hornbach.de: SAP API Gateway confirmed (Server: Gateway, X-CorrelationID); root 404 JSON; backend leak via Host header on /healthcheck → localhost:8080
- CHANGED auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed; redirects to /logon/LogonPoint/tmindex.html; CSP shows img-src http://localhost:*

## 2026-09-06 11:22:06 UTC

## 2026-09-06 14:41:37 UTC
- NEW auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (2026-09-06 06:30Z) — all 6 service endpoints + status advertised; metadata rot flag rejected
- NEW auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating unauthenticated flaw to introspect/revoke only
- NEW auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["public"]` — sub non-pairwise across clients
- CHANGED auth.hornbach.com/authz-srv/authz: previously-200 endpoint may now be deprecated/blocked on cidaas router level — 16:58Z probe showed 404 for `/authz-srv/authz?...token-srv` apart from `introspect`; c
- CHANGED api.hornbach.de: continue to confirm SAP APIM Gateway (Server: Gateway, X-CorrelationID) with 404 JSON root and Host-header backend leak → localhost:8080 on /healthcheck; no new anonymous route discov

## 2026-09-06 17:40:53 UTC

## 2026-09-06 19:37:59 UTC

## 2026-09-06 21:45:07 UTC
- NEW auth.hornbach.de/nitro/v1/config: 302 → /logon/LogonPoint/tmindex.html — Citrix NetScaler mgmt API NOT exposed unauthenticated (redirect gate closes nitro surface); tmindex.html 200 len=43162
- CHANGED api.hornbach.de: root 404 len=47 + /healthcheck 200 len=19 (Via sapigwprd01) re-confirmed 21:43Z — SAP APIM anonymous surface unchanged
- CHANGED auth.hornbach.com/.well-known/status: 200 status endpoint live 21:43Z — unchanged
- NEW auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (2026-09-06 06:30Z) — all 6 service endpoints + status advertised; metadata rot flag rejected
- NEW auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating unauthenticated flaw to introspect/revoke only
- NEW auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["public"]` — sub non-pairwise across clients
- CHANGED auth.hornbach.com/authz-srv/authz: previously-200 endpoint may now be deprecated/blocked on cidaas router level — 16:58Z probe showed 404 for `/authz-srv/authz?...` apart from `introspect`
- CHANGED api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, sap/bc/adt/discovery, sap/public/ping) — all 404 uniform (47 bytes);

## 2026-09-06 23:38:37 UTC
- CHANGED auth.hornbach.com/authz-srv/authz: previously-200 endpoint may now be deprecated/blocked on cidaas router level — 16:58Z probe showed 404 for `/authz-srv/authz?...` apart from `introspect`
- NEW auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating unauthenticated flaw to introspect/revoke only
- NEW auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["public"]` — sub non-pairwise across clients
- CHANGED api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, sap/bc/adt/discovery, sap/public/ping) — all 404 uniform (47 bytes);
- NEW auth.hornbach.de/nitro/v1/config: 302 → /logon/LogonPoint/tmindex.html — Citrix NetScaler mgmt API NOT exposed unauthenticated (redirect gate closes nitro surface)

## 2026-09-07 01:21:14 UTC

## 2026-09-07 06:14:58 UTC

## 2026-09-07 12:52:49 UTC
- CHANGED auth.hornbach.com/token-srv/introspect: probe-results.md shows 15 consecutive GET probes returning 404 (latest 2026-09-07 06:15), but KB confirms POST → 200 `{"active":false}` unauthenticated across 9
- CHANGED auth.hornbach.com/token-srv/revoke: probe-results.md shows 15 consecutive GET probes returning 404 (latest 2026-09-07 06:15), but KB confirms POST → 200 `OK` unauthenticated across 9+ sessions; method
- CHANGED auth.hornbach.com/authz-srv/authz: probe-results.md shows 200 responses with `<valid_client_id>` placeholder; KB notes router-level deprecation signal (404 at 16:58Z 2026-09-06) but OIDC discovery sti
- NEW auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (2026-09-06 06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot flag
- CHANGED api.hornbach.de: 13+ common API paths exhausted (graphql, openapi, swagger, actuator, sap/*) — all uniform 404 (47 bytes); anonymous surface breadth definitively exhausted per KB
- CHANGED auth.hornbach.de/nitro/v1/config: 302 → /logon/LogonPoint/tmindex.html — NetScaler management API confirmed NOT exposed unauthenticated

## 2026-09-07 18:14:16 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST method confirmed as only working method (GET/HEAD return 404); 9+ independent sessions confirm POST → 200 `{"active":false}` unauthenticated
- NEW auth.hornbach.com/token-srv/revoke: POST method confirmed as only working method (GET/HEAD return 404); 9+ sessions confirm POST → 200 `OK` unauthenticated (text/plain)
- CHANGED auth.hornbach.com/authz-srv/authz: router-level deprecation signal (404 at 2026-09-06 16:58Z) but OIDC discovery still advertises endpoint; status uncertain — may be tenant-specific routing
- NEW auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (2026-09-06 06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot flag
- CHANGED api.hornbach.de: 13+ common API paths exhausted (graphql, openapi, swagger, actuator, sap/*) — all uniform 404 (47 bytes); anonymous surface breadth definitively exhausted
- CHANGED auth.hornbach.de/nitro/v1/config: 302 → /logon/LogonPoint/tmindex.html — NetScaler management API confirmed NOT exposed unauthenticated

## 2026-09-07 21:38:18 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST method confirmed as only working method (GET/HEAD return 404); 9+ independent sessions confirm POST → 200 `{"active":false}` unauthenticated — methodology 
- NEW auth.hornbach.com/token-srv/revoke: POST method confirmed as only working method (GET/HEAD return 404); 9+ sessions confirm POST → 200 `OK` unauthenticated (text/plain) — methodology artifact identifi
- CHANGED auth.hornbach.com/authz-srv/authz: router-level deprecation signal (404 at 2026-09-06 16:58Z) but OIDC discovery still advertises endpoint; status uncertain — may be tenant-specific routing; RE-CONFIR
- NEW auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (2026-09-06 06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot flag
- CHANGED api.hornbach.de: 13+ common API paths exhausted (graphql, openapi, swagger, actuator, sap/*) — all uniform 404 (47 bytes); anonymous surface breadth definitively exhausted
- CHANGED auth.hornbach.de/nitro/v1/config: 302 → /logon/LogonPoint/tmindex.html — NetScaler management API confirmed NOT exposed unauthenticated
- NEW auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo is single consuming gate on token plane

## 2026-09-07 23:49:07 UTC
- NEW auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo is single consuming gate on token plane (2026-09-07 21:38)
- CHANGED auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z 2026-09-07 — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:58 deprecation/404 flag as transient shared-routing 
- CHANGED auth.hornbach.com/token-srv/introspect: POST method confirmed as only working method (GET/HEAD return 404); 10th session 18:13Z confirms POST → 200 `{"active":false}` unauthenticated — methodology art
- CHANGED auth.hornbach.com/token-srv/revoke: POST method confirmed as only working method (GET/HEAD return 404); 10th session 18:13Z confirms POST → 200 `OK` unauthenticated (text/plain) — methodology artifact

## 2026-09-08 03:54:37 UTC
- NEW auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo is single consuming gate on token plane (2026-09-07 21:38)
- CHANGED auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z 2026-09-07 — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:58 deprecation/404 flag as transient shared-routing 
- CHANGED auth.hornbach.com/token-srv/introspect: POST method confirmed as only working method (GET/HEAD return 404); 10th session 18:13Z confirms POST → 200 `{"active":false}` unauthenticated — methodology art
- CHANGED auth.hornbach.com/token-srv/revoke: POST method confirmed as only working method (GET/HEAD return 404); 10th session 18:13Z confirms POST → 200 `OK` unauthenticated (text/plain) — methodology artifact

## 2026-09-08 08:49:28 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 `{"active":false}` unauthenticated confirmed across 10+ sessions; systemic and stable
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 `OK` unauthenticated confirmed stable; text/plain response body
- NEW auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; deprecation flag rejected
- NEW auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist
- NEW api.hornbach.de: SAP API Gateway exists with backend on localhost:8080; anonymous breadth definitively exhausted
- NEW hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- NEW auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo is single consuming gate on token plane (2026-09-07 21:38)
- CHANGED auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z 2026-09-07 — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:58 deprecation/404 flag as transient shared-routing 
- CHANGED auth.hornbach.com/token-srv/introspect: POST method confirmed as only working method (GET/HEAD return 404); 10th session 18:13Z confirms POST → 200 `{"active":false}` unauthenticated — methodology art
- CHANGED auth.hornbach.com/token-srv/revoke: POST method confirmed as only working method (GET/HEAD return 404); 10th session 18:13Z confirms POST → 200 `OK` unauthenticated (text/plain) — methodology artifact

## 2026-09-08 13:30:46 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 `{"active":false}` unauthenticated confirmed across 10+ independent sessions; systemic and stable (GET/HEAD 404 was methodology artifact)
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 `OK` unauthenticated confirmed stable across 10+ sessions; text/plain response body; parameter-sensitive 404 on GET/HEAD
- NEW auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE at 18:13Z 2026-09-07 — 302→AUTH10007 invalid_client on dummy client_id; rejects 2026-09-06 deprecation flag as transient routing noise
- NEW auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo is single consuming gate on token plane
- NEW api.hornbach.de: SAP APIM Gateway confirmed (Server: Gateway, Via sapigwprd01/02, X-CorrelationID) with backend leak localhost:8080 via /healthcheck; 21+ common paths exhausted — anonymous surface bre
- NEW hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace v3.1301 confirmed in-scope; all /api/* require Mirakl auth
- CHANGED auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot hypothesis
- CHANGED auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` — token plane client-gated, isolating unauthenticated flaw to introspect/revoke only
- CHANGED auth.hornbach.com: discovery advertises `token-exchange` (RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["public"]` — sub non-pairwise across clients
- CHANGED auth.hornbach.de/nitro/v1/config: 302→/logon/LogonPoint/tmindex.html — NetScaler management API NOT exposed unauthenticated

## 2026-09-08 17:33:24 UTC

## 2026-09-08 20:19:01 UTC

## 2026-09-08 22:50:56 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 {"active":false} unauthenticated confirmed 11th session (13:27Z 2026-09-08); systemic and stable across 11+ independent sessions
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 OK unauthenticated confirmed 11th session (13:27Z 2026-09-08); stable text/plain response; parameter-sensitive 404 on GET/HEAD
- NEW auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z 2026-09-08 — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enumeration REMOVED
- NEW auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-only route)
- CHANGED auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous logout CSRF vector (REJECTED)
- CHANGED hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S256) — Mirakl federates OUTSIDE cidaas, not a client_id source f
- CHANGED api.hornbach.de: OPTIONS/TRACE in Allow header REJECTED per scope rules
- CHANGED auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## 2026-09-09 01:17:49 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 {"active":false} unauthenticated confirmed 11th session (13:27Z 2026-09-08); systemic and stable across 11+ independent sessions (KB)
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 OK unauthenticated confirmed 11th session (13:27Z 2026-09-08); stable text/plain response; parameter-sensitive 404 on GET/HEAD (KB)
- NEW auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z 2026-09-08 — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enumeration REMOVED (KB)
- NEW auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-only route) (KB)
- CHANGED auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous logout CSRF vector (REJECTED)
- CHANGED hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S256) — Mirakl federates OUTSIDE cidaas, not a client_id source f
- CHANGED api.hornbach.de: OPTIONS/TRACE in Allow header REJECTED per scope rules
- CHANGED auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## 2026-09-09 06:13:02 UTC

## 2026-09-09 11:46:39 UTC
- CHANGED auth.hornbach.com/token-srv/introspect: probe-results.md shows 25+ consecutive GET probes returning 404 (latest 2026-09-09 06:13), but KB confirms POST → 200 `{"active":false}` unauthenticated across 
- CHANGED auth.hornbach.com/token-srv/revoke: probe-results.md shows 25+ consecutive GET probes returning 404 (latest 2026-09-09 06:13), but KB confirms POST → 200 `OK` unauthenticated across 11+ sessions; para

## 2026-09-09 15:26:03 UTC
- NEW probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-09 06:13), but KB confirms POST → 200 works across 11+ sessions; methodolo
- NEW auth.hornbach.com/authz-srv/authz RE-CONFIRMED LIVE at 13:27Z 2026-09-08 — 302→AUTH10007 on dummy client_id; uniform gate, client_id enum REMOVED
- CHANGED No new assets discovered; attack surface stable; only gate remains valid client_id extraction from mobile app

## 2026-09-09 18:46:37 UTC
- NEW probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-09 15:26), but KB confirms POST → 200 works across 11+ sessions; methodolo
- NEW auth.hornbach.com/users-srv/userinfo consistently returns HTTP 401 JSON (bearer-gated) across last 10+ probe sessions; token-srv/userinfo → 404 confirmed router gap
- CHANGED No new assets discovered since 2026-09-08; attack surface stable; only gate remains valid client_id extraction from mobile app (de.hornbach.app.smarthome)
- CHANGED auth.hornbach.com/authz-srv/authz RE-CONFIRMED LIVE at 13:27Z 2026-09-08 — 302→AUTH10007 on dummy client_id; uniform gate, client_id enum REMOVED

## 2026-09-09 21:36:15 UTC
- NEW probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-09 18:46), but KB confirms POST → 200 works across 11+ sessions; methodolo
- NEW auth.hornbach.com/users-srv/userinfo consistently returns HTTP 401 JSON (bearer-gated) across last 10+ probe sessions; token-srv/userinfo → 404 confirmed router gap
- CHANGED No new assets discovered since 2026-09-08; attack surface stable; only gate remains valid client_id extraction from mobile app (de.hornbach.app.smarthome)
- CHANGED auth.hornbach.com/authz-srv/authz RE-CONFIRMED LIVE at 13:27Z 2026-09-08 — 302→AUTH10007 on dummy client_id; uniform gate, client_id enum REMOVED

## 2026-09-09 23:34:33 UTC

## 2026-09-10 01:31:59 UTC
- NEW No new assets discovered since 2026-09-08; attack surface stable across auth.hornbach.com (cidaas), api.hornbach.de (SAP APIM), auth.hornbach.de (Citrix NetScaler), hornbach-mp.mirakl.net (Mirakl)
- CHANGED probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-09 23:34), but KB confirms POST → 200 works across 11+ independent session
- CHANGED auth.hornbach.com/users-srv/userinfo consistently returns HTTP 401 JSON (bearer-gated) across last 10+ probe sessions; token-srv/userinfo → 404 confirmed router gap
- CHANGED auth.hornbach.com/authz-srv/authz RE-CONFIRMED LIVE at 13:27Z 2026-09-08 — 302→AUTH10007 on dummy client_id; uniform gate, client_id enumeration REMOVED
- CHANGED hornbach-mp.mirakl.net federates to login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S256) — NOT a client_id source for auth.hornbach.com tenant
- NEW No new assets discovered since 2026-09-08; attack surface stable across auth.hornbach.com (cidaas), api.hornbach.de (SAP APIM), auth.hornbach.de (Citrix NetScaler), hornbach-mp.mirakl.net (Mirakl)
- CHANGED probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-09 23:34), but KB confirms POST → 200 works across 11+ independent session
- CHANGED auth.hornbach.com/users-srv/userinfo consistently returns HTTP 401 JSON (bearer-gated) across last 10+ probe sessions; token-srv/userinfo → 404 confirmed router gap
- CHANGED auth.hornbach.com/authz-srv/authz RE-CONFIRMED LIVE at 13:27Z 2026-09-08 — 302→AUTH10007 on dummy client_id; uniform gate, client_id enumeration REMOVED
- CHANGED hornbach-mp.mirakl.net federates to login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S256) — NOT a client_id source for auth.hornbach.com tenant

## 2026-09-10 06:46:13 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 `{"active":false}` unauthenticated confirmed 11th independent session (2026-09-08 13:27Z); systemic and stable across 11+ sessions; GET/HEAD 404 was 
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 `OK` unauthenticated confirmed 11th session (2026-09-08 13:27Z); stable text/plain response; parameter-sensitive 404 on GET/HEAD
- NEW auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z 2026-09-08 — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enumeration REMOVED
- NEW auth.hornbach.com/users-srv/userinfo: consistently returns HTTP 401 JSON (bearer-gated) across 10+ probe sessions; token-srv/userinfo → 404 confirmed router gap
- NEW hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S256) — Mirakl federates OUTSIDE cidaas, not a client_id source f
- CHANGED probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-09 23:34), but KB confirms POST → 200 works across 11+ independent session
- CHANGED auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot hypothesis
- CHANGED No new assets discovered since 2026-09-08; attack surface stable across auth.hornbach.com (cidaas), api.hornbach.de (SAP APIM), auth.hornbach.de (Citrix NetScaler), hornbach-mp.mirakl.net (Mirakl)

## 2026-09-10 12:06:57 UTC

## 2026-09-10 16:16:28 UTC
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 {"active":false} unauthenticated confirmed 12th session (2026-09-10 01:29Z); systemic and stable across 12+ sessions; GET/HEAD 404 was methodology ar
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 OK unauthenticated confirmed 12th session; stable text/plain; parameter-sensitive 404 on GET/HEAD
- NEW auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enumeration REMOVED
- CHANGED probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-10 06:46), but KB confirms POST → 200 works across 12+ independent session
- CHANGED auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot hypothesis
- CHANGED No new assets discovered since 2026-09-08; attack surface stable across auth.hornbach.com (cidaas), api.hornbach.de (SAP APIM), auth.hornbach.de (Citrix NetScaler), hornbach-mp.mirakl.net (Mirakl)
- CHANGED hornbach-mp.mirakl.net federates to login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S256) — NOT a client_id source for auth.hornbach.com tenant

## 2026-09-10 19:11:18 UTC
- CHANGED `auth.hornbach.com/`: root is F5 Shape bot-challenge (not cidaas login UI) — `_fs-ch-*` assets, CSP, noscript fallback. 0 cidaas config exposed. Hypothesis #3 (root HTML client_id extraction) is dead 
- NEW auth.hornbach.com/token-srv/introspect: POST → 200 {"active":false} unauthenticated confirmed 12th session (2026-09-10 01:29Z); systemic and stable across 12+ sessions; GET/HEAD 404 was methodology ar
- NEW auth.hornbach.com/token-srv/revoke: POST → 200 OK unauthenticated confirmed 12th session; stable text/plain; parameter-sensitive 404 on GET/HEAD
- NEW auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enumeration REMOVED
- CHANGED probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-10 06:46), but KB confirms POST → 200 works across 12+ independent session
- CHANGED auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot hypothesis
- CHANGED No new assets discovered since 2026-09-08; attack surface stable across auth.hornbach.com (cidaas), api.hornbach.de (SAP APIM), auth.hornbach.de (Citrix NetScaler), hornbach-mp.mirakl.net (Mirakl)
- CHANGED hornbach-mp.mirakl.net federates to login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S256) — NOT a client_id source for auth.hornbach.com tenant

## 2026-09-10 21:46:49 UTC
- CHANGED `auth.hornbach.com/` root is now F5 Shape Security bot-challenge (`_fs-ch-*` assets, CSP, noscript fallback), NOT cidaas login UI — 0 cidaas config exposed; root HTML client_id extraction hypothesis d
- CHANGED `probe-results.md` shows 25+ consecutive GET probes returning 404 for `token-srv/introspect` and `token-srv/revoke` (latest 2026-09-10 19:11), but KB confirms POST → 200 works across 12+ independent s
- NEW `auth.hornbach.com/token-srv/introspect`: POST → 200 `{"active":false}` unauthenticated confirmed 12th session (2026-09-10 01:29Z); systemic and stable
- NEW `auth.hornbach.com/token-srv/revoke`: POST → 200 OK unauthenticated confirmed 12th session; stable text/plain; parameter-sensitive 404 on GET/HEAD
- NEW `auth.hornbach.com/authz-srv/authz`: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enumeration REMOVED
- CHANGED `auth.hornbach.com/.well-known/openid-configuration`: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot hypothesis
- CHANGED No new assets discovered since 2026-09-08; attack surface stable across auth.hornbach.com (cidaas), api.hornbach.de (SAP APIM), auth.hornbach.de (Citrix NetScaler), hornbach-mp.mirakl.net (Mirakl)

## 2026-09-10 23:53:47 UTC
- CHANGED `auth.hornbach.com/` root is now F5 Shape Security bot-challenge (`_fs-ch-*` assets, CSP, noscript fallback), NOT cidaas login UI — 0 cidaas config exposed; root HTML client_id extraction hypothesis d
- CHANGED `probe-results.md` shows 25+ consecutive GET probes returning 404 for `token-srv/introspect` and `token-srv/revoke` (latest 2026-09-10 21:46), but KB confirms POST → 200 works across 12+ independent s
- NEW `auth.hornbach.com/token-srv/introspect`: POST → 200 `{"active":false}` unauthenticated confirmed 12th session (2026-09-10 01:29Z); systemic and stable
- NEW `auth.hornbach.com/token-srv/revoke`: POST → 200 OK unauthenticated confirmed 12th session; stable text/plain; parameter-sensitive 404 on GET/HEAD
- NEW `auth.hornbach.com/authz-srv/authz`: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enumeration REMOVED
- CHANGED `auth.hornbach.com/.well-known/openid-configuration`: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot hypothesis
- CHANGED No new assets discovered since 2026-09-08; attack surface stable across auth.hornbach.com (cidaas), api.hornbach.de (SAP APIM), auth.hornbach.de (Citrix NetScaler), hornbach-mp.mirakl.net (Mirakl)

## 2026-09-11 03:52:49 UTC
- CHANGED `auth.hornbach.com/`: root is F5 Shape bot-challenge (not cidaas login UI) — `_fs-ch-*` assets, CSP, noscript fallback. 0 cidaas config exposed. Hypothesis #3 (root HTML client_id extraction) is dead 
- NEW `hornbach.com/.de/.at/.nl/.ch` + `login.hornbach.com/` ALL serve identical 3038-byte F5 "Client Challenge" stub — international TLD estate adds NO client_id extraction bypass; last web-based cidaas cl
- NEW `auth.hornbach.com/token-srv/token`: POST `grant_type=authorization_code` + bogus client → 400 `invalid_client` "unknown client" — confirms invalid_client-vs-invalid_grant differential exists ONLY in 
- NEW `auth.hornbach.com/` root rotated to F5 Shape Security bot-challenge (`_fs-ch-*` assets, CSP, noscript fallback) — 0 cidaas config exposed; prior root HTML client_id extraction hypothesis dead (confir
- CHANGED `probe-results.md` shows 25+ consecutive GET probes returning 404 for `token-srv/introspect` and `token-srv/revoke` (latest 2026-09-10 23:53), but KB confirms POST → 200 works across 12+ independent s
- NEW `auth.hornbach.com/token-srv/introspect`: POST → 200 `{"active":false}` unauthenticated confirmed 12th session (2026-09-10 01:29Z); systemic and stable
- NEW `auth.hornbach.com/token-srv/revoke`: POST → 200 OK unauthenticated confirmed 12th session; stable text/plain; parameter-sensitive 404 on GET/HEAD
- NEW `auth.hornbach.com/authz-srv/authz`: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enumeration REMOVED
- CHANGED `auth.hornbach.com/.well-known/openid-configuration`: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; rejects metadata-rot hypothesis
- CHANGED No new assets discovered since 2026-09-08; attack surface stable across auth.hornbach.com (cidaas), api.hornbach.de (SAP APIM), auth.hornbach.de (Citrix NetScaler), hornbach-mp.mirakl.net (Mirakl)

## 2026-09-11 08:49:14 UTC
- CHANGED `auth.hornbach.com/` root: now returns 302 → hornbach.de (was 200 len=3038 F5 challenge). CSP header confirms cidaas backend (x-powered-by: cidaas). Follow chain: hornbach.de → 301 → www.hornbach.de →
- NEW `auth.hornbach.com/` CSP header exposed: `default-src 'self'; script-src 'self'; img-src 'self' https:` — restrictive, no inline script; no client_id in root response headers.
- NEW `auth.hornbach.com/` root rotated to F5 Shape Security bot-challenge (`_fs-ch-*` assets, CSP, noscript fallback) — 0 cidaas config exposed; prior root HTML client_id extraction hypothesis dead (confir
- NEW `hornbach.com` international TLDs (.de/.at/.nl/.ch) + `login.hornbach.com/` ALL serve identical 3038-byte F5 "Client Challenge" stub — estate-wide bot-wall closes last web-based cidaas client_id extra
- NEW `auth.hornbach.com/token-srv/token`: POST `grant_type=authorization_code` + bogus client → 400 `invalid_client` "unknown client" — confirms token plane client-gated; invalid_client-vs-invalid_grant di
- CHANGED `probe-results.md` shows 25+ consecutive GET probes returning 404 for `token-srv/introspect` and `token-srv/revoke` (latest 2026-09-10 23:53), but KB confirms POST → 200 works across 12+ independent s
- CHANGED No new assets discovered since 2026-09-08; attack surface stable across auth.hornbach.com (cidaas), api.hornbach.de (SAP APIM), auth.hornbach.de (Citrix NetScaler), hornbach-mp.mirakl.net (Mirakl)

## 2026-09-11 13:35:17 UTC
- NEW `auth.hornbach.com/` root now returns 302 → hornbach.de (was 200 len=3038 F5 challenge). CSP header confirms cidaas backend (`x-powered-by: cidaas`). Follow chain: hornbach.de → 301 → www.hornbach.de 
- NEW `hornbach.com` international TLDs (.de/.at/.nl/.ch) + `login.hornbach.com/` ALL serve identical 3038-byte F5 "Client Challenge" stub — estate-wide bot-wall closes last web-based cidaas client_id extra
- NEW `auth.hornbach.com/token-srv/token`: POST `grant_type=authorization_code` + bogus client → 400 `invalid_client` "unknown client" — confirms token plane client-gated; invalid_client-vs-invalid_grant di
- CHANGED `probe-results.md` shows 25+ consecutive GET probes returning 404 for `token-srv/introspect` and `token-srv/revoke` (latest 2026-09-11 08:49), but KB confirms POST → 200 works across 12+ independent s
- CHANGED `auth.hornbach.com/.well-known/openid-configuration` RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised; rejects metadata-rot hypothesis.

## 2026-09-11 17:24:11 UTC
- NEW auth.hornbach.com/ root now returns 302 → hornbach.de (was 200 len=3038 F5 challenge). CSP header confirms cidaas backend (x-powered-by: cidaas). Chain: hornbach.de → 301 → www.hornbach.de → bot chall
- NEW hornbach.com international TLDs (.de/.at/.nl/.ch) + login.hornbach.com/ ALL serve identical 3038-byte F5 "Client Challenge" stub — estate-wide bot-wall closes last web-based cidaas client_id extractio
- NEW auth.hornbach.com/token-srv/token: POST grant_type=authorization_code + bogus client → 400 invalid_client "unknown client" — confirms token plane client-gated; invalid_client-vs-invalid_grant differen
- CHANGED probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-11 08:49), but KB confirms POST → 200 works across 12+ independent session
- CHANGED auth.hornbach.com/.well-known/openid-configuration RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised; rejects metadata-rot hypothesis.
- CHANGED auth.hornbach.com/authz-srv/authz RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enumeration REMOVED.

## 2026-09-11 19:57:09 UTC
- CHANGED auth.hornbach.com/ root: now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend (x-powered-by: cidaas); chain: hornbach.de → 301 → www.hornbach.de → bot chal
- CHANGED hornbach.com international TLDs (.de/.at/.nl/.ch) + login.hornbach.com/ ALL serve identical 3038-byte F5 "Client Challenge" stub — estate-wide bot-wall closes last web-based cidaas client_id extractio
- CHANGED probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-11 08:49), but KB confirms POST → 200 works across 14+ independent session

## 2026-09-11 22:24:48 UTC
- NEW auth.hornbach.com/ root: now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend (x-powered-by: cidaas); chain: hornbach.de → 301 → www.hornbach.de → bot chal
- NEW hornbach.com international TLDs (.de/.at/.nl/.ch) + login.hornbach.com/ ALL serve identical 3038-byte F5 "Client Challenge" stub — estate-wide bot-wall closes last web-based cidaas client_id extractio
- CHANGED probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-11 08:49), but KB confirms POST → 200 works across 14+ independent session
- CHANGED auth.hornbach.com/authz-srv/authz RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- CHANGED auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated; client-validation-ordering (AUTH10008/10009) fired only afte

## 2026-09-12 00:44:17 UTC
- NEW auth.hornbach.com/ root: now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend (x-powered-by: cidaas); chain: hornbach.de → 301 → www.hornbach.de → bot chal
- NEW hornbach.com international TLDs (.de/.at/.nl/.ch) + login.hornbach.com/ ALL serve identical 3038-byte F5 "Client Challenge" stub — estate-wide bot-wall closes last web-based cidaas client_id extractio
- CHANGED probe-results.md shows 25+ consecutive GET probes returning 404 for token-srv/introspect and token-srv/revoke (latest 2026-09-11 08:49), but KB confirms POST → 200 works across 14+ independent session
- CHANGED auth.hornbach.com/authz-srv/authz RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- CHANGED auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated; client-validation-ordering (AUTH10008/10009) fired only afte
