# Hypotheses (ranked)

## RANKED HYPOTHESES 2026-09-02 21:46:10 UTC

## RANKED HYPOTHESES 2026-09-02 23:55:43 UTC

## RANKED HYPOTHESES 2026-09-03 03:44:54 UTC

## RANKED HYPOTHESES 2026-09-03 08:47:26 UTC

## RANKED HYPOTHESES 2026-09-03 13:26:05 UTC

## RANKED HYPOTHESES 2026-09-03 17:21:30 UTC
- [65] auth.hornbach.com: cidaas OAuth redirect_uri validation bypass (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: GET https://auth.hornbach.com/ -v --max-redirs 0 to capture initial redirect chain and query parameters (client_id, redirect_uri, state) for OAuth flow a
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://auth.hornbach.com/oauth2/authorize?response_type=code&client_id=public&redirect_uri=https://example.com&scope=openid — observe redirect_uri v
- LEARN: REJECTED class WILDCARD_DOM: wildcard DNS dominates hornbach.com zone; no dedicated hosts recovered; move to CDN-proxied surface analysis instead of subdomain e
- LEARN: ACCEPTED class OATH: third-party IdP (cidaas) integration on auth.hornbach.com creates OAuth/OIDC attack surface worth investigating
- LEARN: REJECTED MISCONFIG @ login.hornbach.com: Fastly shared SNI CNAME takeover unlikely without Fastly account access; active service confirmed via Varnish header an

## RANKED HYPOTHESES 2026-09-03 20:03:14 UTC
- [55] auth.hornbach.com/apps-srv/clients/register: Unauthenticated OAuth client registration via apps-srv/clients/register (from art/lead_bigpickle.txt)
- [50] auth.hornbach.com/oauth2/authorize: cidaas OAuth client_id enumeration via authorize endpoint (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: GET https://auth.hornbach.com/ -v — parse HTML/JS for cidaas client_id, OAuth config, or API endpoints; then test discovered client_id against /oauth2/au
- NEXT(hypotheses-bigpickle.txt): PROBE: curl -s -D- -X POST https://auth.hornbach.com/apps-srv/clients/register -H "Content-Type: application/json" -d '{"client_name":"test_probe","redirect_uri
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com: cidaas OAuth surface confirmed live; client_id enumeration is prerequisite for redirect_uri/state flaw testing.
- LEARN: REJECTED class WILDCARD_DOM: reconfirmed — wildcard DNS dominates zone; no new subdomains via passive enumeration.
- LEARN: ACCEPTED class AUTH: cidaas CIAM platform on auth.hornbach.com exposes full OIDC provider metadata including registration_endpoint, device_authorization_endpoin
- LEARN: ACCEPTED class OATH: Authorization endpoint confirmed live at authz-srv/authz with verbose error messages; redirect_uri validation testing requires valid client

## RANKED HYPOTHESES 2026-09-03 22:31:53 UTC
- [55] auth.hornbach.com/apps-srv/clients/register: Unauthenticated OAuth client registration via apps-srv/clients/register (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: curl -s -D- -X POST https://auth.hornbach.com/apps-srv/clients/register -H "Content-Type: application/json" -d '{"client_name":"test_probe","redirect_uri
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com: cidaas OAuth surface confirmed live; client_id enumeration is prerequisite for redirect_uri/state flaw testing.
- LEARN: REJECTED class WILDCARD_DOM: reconfirmed — wildcard DNS dominates zone; no new subdomains via passive enumeration.
- LEARN: ACCEPTED class AUTH: cidaas CIAM platform on auth.hornbach.com exposes full OIDC provider metadata including registration_endpoint, device_authorization_endpoin
- LEARN: ACCEPTED class OATH: Authorization endpoint confirmed live at authz-srv/authz with verbose error messages; redirect_uri validation testing requires valid client

## RANKED HYPOTHESES 2026-09-04 00:43:49 UTC

## RANKED HYPOTHESES 2026-09-04 05:17:56 UTC
- [50] auth.hornbach.com/authz-srv/authz: OAuth redirect_uri validation bypass on authz-srv/authz (from art/lead_nemotron3.txt)
- [45] auth.hornbach.com/token-srv/introspect: Unauthenticated token introspection — probing for data exposure via /token-srv/introspect (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: enumerate a valid cidaas client_id from the HORNBACH mobile app (de.hornbach) by obtaining/parsing its OAuth config (client_id + redirect_uri) — required
- NEXT(hypotheses-nemotron3.txt): PROBE: curl -s -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com: dynamic OAuth client registration disabled — /apps-srv/clients/register 404 on all methods; metadata endpoint exis
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: separate Citrix NetScaler AAA VPN Gateway surface exists on hornbach.de, distinct from cidaas .com — legacy employee acc
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is an in-scope API surface; all /api/* require Mirakl auth
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: API gateway exists (Gateway server header) but no documented endpoints discovered at common paths

## RANKED HYPOTHESES 2026-09-04 09:58:02 UTC
- [50] auth.hornbach.com/token-srv/introspect: Unauthenticated token introspection leaks token metadata (from art/lead_bigpickle.txt)
- [50] auth.hornbach.com/authz-srv/authz: OAuth redirect_uri validation bypass via regex/wildcard mismatch on authz-srv/authz (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: Obtain valid cidaas client_id from HORNBACH mobile app (de.hornbach) by downloading APK/IPA and extracting OAuth config (client_id + redirect_uri scheme)
- NEXT(hypotheses-bigpickle.txt): HUMAN: The critical unlock for all OAuth hypotheses is obtaining a valid cidaas client_id. Options: (1) extract from HORNBACH mobile app (de.hornbach on Google 
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: token introspection endpoint accessible unauthenticated, RFC 7662 compliant (returns active=false)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: API gateway exists (Gateway server header) but no documented endpoints discovered at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway surface confirmed (legacy employee access)

## RANKED HYPOTHESES 2026-09-04 14:20:23 UTC
- [55] auth.hornbach.com/token-srv/revoke: Unauthenticated token revocation enables silent session killing (from art/lead_bigpickle.txt)
- [50] auth.hornbach.com/authz-srv/authz: OAuth redirect_uri validation bypass via regex/wildcard mismatch on authz-srv/authz (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: The critical unlock is obtaining a valid cidaas client_id. cidaas Android SDK stores it as `<item name="ClientId" type="string">` in cidaas.xml or string
- NEXT(hypotheses-nemotron3.txt): PROBE: Obtain valid cidaas client_id from HORNBACH mobile app (de.hornbach) by downloading APK from Google Play and extracting OAuth config (client_id + redirec
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: token revocation endpoint accessible unauthenticated, RFC 7009 violation — second token management end
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: unauthenticated introspection confirmed systemic; strengthened by parallel revoke finding
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: token introspection endpoint now returns 404 (was accessible unauthenticated, RFC 7662 compliant r
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-04 17:49:13 UTC
- [55] auth.hornbach.com/token-srv/revoke: Unauthenticated token revocation enables silent session killing (from art/lead_bigpickle.txt)
- [50] auth.hornbach.com/authz-srv/authz: OAuth redirect_uri validation bypass via regex/wildcard mismatch on authz-srv/authz (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: The critical unlock for all OAuth hypotheses is obtaining a valid cidaas client_id. cidaas Android SDK stores it as `<item name="ClientId" type="string">
- NEXT(hypotheses-nemotron3.txt): PROBE: Obtain valid cidaas client_id from HORNBACH mobile app (de.hornbach) by downloading APK from Google Play and extracting OAuth config (client_id + redirec
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: token revocation endpoint accessible unauthenticated, RFC 7009 violation — second token management end
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: unauthenticated introspection confirmed systemic; strengthened by parallel revoke finding
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: token introspection endpoint now returns 404 (was accessible unauthenticated, RFC 7662 compliant r
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: token revocation endpoint accessible unauthenticated, RFC 7009 violation — second token management end
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-04 20:01:29 UTC
- [60] auth.hornbach.com/token-srv/{revoke,introspect}: Unauthenticated token revocation + introspection pair enables silent session killing + metadata leak (from art/lead_bigpickle.txt)
- [50] auth.hornbach.com/authz-srv/authz: OAuth redirect_uri validation bypass via regex/wildcard mismatch on authz-srv/authz (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Obtain a valid cidaas client_id — the single blocker gating escalation of the confirmed unauthenticated token-management bypass. Best sources: (1) HORNBA
- NEXT(hypotheses-nemotron3.txt): PROBE: Obtain valid cidaas client_id from HORNBACH mobile app (de.hornbach) by downloading APK from Google Play and extracting OAuth config (client_id + redirec
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated — prior "404" was transient; unaut
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated — two stable unauthenticated token management endp
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: token introspection endpoint now returns 404 (was accessible unauthenticated, RFC 7662 compliant r
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: token revocation endpoint accessible unauthenticated, RFC 7009 violation — second token management end
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-04 22:16:10 UTC
- [65] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation persists (RFC 7662/7009 systemic bypass) (from art/lead_bigpickle.txt)
- [55] auth.hornbach.com/authz-srv/authz: OAuth redirect_uri validation bypass via regex/wildcard mismatch on authz-srv/authz (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Obtain a valid cidaas client_id — sole blocker for turning the confirmed 200/200 unauthenticated token-plane bypass into a reportable PoC. Deterministic 
- NEXT(hypotheses-nemotron3.txt): PROBE: Obtain valid cidaas client_id from HORNBACH mobile app (de.hornbach) by downloading APK from Google Play and extracting OAuth config (client_id + redirec
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated — prior "404" was transient; unaut
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated — two stable unauthenticated token management endp
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-05 00:15:30 UTC
- [70] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token-plane bypass remains systemic across days (RFC 7662/7009) (from art/lead_bigpickle.txt)
- [65] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation pair enables silent session killing + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Extract a valid cidaas `client_id` from the de.hornbach Android APK (download from APKMirror, unzip, grep `cidaas.xml`/`strings.xml` for the ClientId ent
- NEXT(hypotheses-nemotron3.txt): PROBE: Obtain valid cidaas client_id from HORNBACH mobile app (de.hornbach) by downloading APK from Google Play and extracting OAuth config (client_id + redirec
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated — prior "404" was transient; unaut
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated — two stable unauthenticated token management endp
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-05 04:42:29 UTC
- [70] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation pair enables silent session killing + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): PROBE: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated — prior "404" was transient; unaut
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated — two stable unauthenticated token management endp
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-05 08:45:24 UTC
- [70] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation pair enables silent session killing + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- NEXT(hypotheses-nemotron3.txt): PROBE: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated — prior "404" was transient; unaut
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated — two stable unauthenticated token management endp
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated — prior "404" was transient; unaut
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated — two stable unauthenticated token management endp
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated via POST — prior "404" was transie
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated via POST — two stable unauthenticated token manage
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-05 12:18:39 UTC
- [78] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token-management plane bypass — introspect JSON+form, revoke, both zero client auth; issuance correctly gated (from art/lead_bigpickle.txt)
- [70] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation pair enables silent session killing + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Obtain a valid cidaas client_id — the sole gate across all three FINAL chains. Revised priority: (1) capture `client_id` from the `/authz-srv/authz` redi
- NEXT(hypotheses-nemotron3.txt): PROBE: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated via POST — prior "404" was transie
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated via POST — two stable unauthenticated token manage
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-05 15:26:18 UTC
- [80] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token-management plane bypass — POST-only, body-presence gate, issuance correctly isolated (from art/lead_bigpickle.txt)
- [75] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation pair enables silent session killing + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Obtain a valid cidaas `client_id` — the single blocker across all escalation chains. Priority: (1) capture `client_id` from the `/authz-srv/authz` redire
- NEXT(hypotheses-nemotron3.txt): PROBE: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 15:22 UTC, 6th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 15:22 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: `client_id=<found>` (literal string) now returns 302→AUTH10003 `invalid_request` (parsing error) — the 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated via POST — prior "404" was transie
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated via POST — two stable unauthenticated token manage
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-05 17:43:13 UTC
- [80] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation pair enables silent session killing + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated via POST — prior "404" was transie
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated via POST — two stable unauthenticated token manage
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-05 19:34:06 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation pair enables silent session killing + metadata leak (from art/lead_nemotron3.txt)
- [60] auth.hornbach.com/token-srv/{revoke,introspect}: Unauthenticated token revocation + introspection pair (RFC 7662/7009 violation, systemic) (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Obtain a valid cidaas client_id — the single blocker gating escalation of the confirmed unauthenticated token-management bypass. Best sources: (1) HORNBA
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated — prior "404" was transient; unaut
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated — two stable unauthenticated token management endp
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated — prior "404" was transient; unaut
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated — two stable unauthenticated token management endp
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED live, returns 200 {"active":false} unauthenticated — prior "404" was transient; unaut
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED live, returns 200 "OK" unauthenticated — two stable unauthenticated token management endp
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 15:22 UTC, 6th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 15:22 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: `client_id=<found>` (literal string) now returns 302→AUTH10003 `invalid_request` (parsing error) — the 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 17:43 UTC, 7th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 17:43 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-05 21:48:55 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token-management plane bypass — POST-only, body-presence gate, issuance isolated (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation pair enables silent session killing + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 17:43 UTC, 7th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 17:43 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302->
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
