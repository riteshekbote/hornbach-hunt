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

## RANKED HYPOTHESES 2026-09-05 23:41:22 UTC
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 23:40 UTC, 8th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 23:40 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-06 01:24:28 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- [55] de.hornbach.app.smarthome: Cross-check: Hornbach Smarthome app leaks cidaas client_id + redirect_uri scheme (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Get `de.hornbach.app.smarthome` APK (VirusTotal/apkfiles/APKMirror), extract `assets/cidaas.xml` → client_id + redirect_uri scheme; feeds both the 85-con
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: REJECTED class OTHER @ auth.hornbach.com/-: metadata endpoints rot suspected → re-fetch of 7 known paths returned 404/302 across [16:52–17:0x], but token-srv/in
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv: previously-200 authz endpoint may now be deprecated/blocked on cidaas router level — 16:58-UTC probe showed 4
- LEARN: REJECTED class OTHER @ auth.hornbach.com: no access-token-leak in `cid-login` (302, no fragment to reflect), but Rudderstack CONFIG endpoint leaked cidaas accou
- LEARN: REJECTED class OTHER @ auth.hornbach.com: oauth/device + oauth/default + logi/srv + pub/src + user-srv + pub/auth with varying params all 404 — No socratic prom
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 23:40 UTC, 8th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 23:40 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-06 06:33:23 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
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
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 23:40 UTC, 8th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 23:40 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 23:40 UTC, 8th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 23:40 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
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
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 23:40 UTC, 8th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 23:40 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 23:40 UTC, 8th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 23:40 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: REJECTED class OTHER @ auth.hornbach.com/-: metadata endpoints rot suspected → re-fetch of 7 known paths returned 404/302 across [16:52–17:0x], but token-srv/in
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv: previously-200 authz endpoint may now be deprecated/blocked on cidaas router level — 16:58-UTC probe showed 4
- LEARN: REJECTED class OTHER @ auth.hornbach.com: no access-token-leak in `cid-login` (302, no fragment to reflect), but Rudderstack CONFIG endpoint leaked cidaas accou
- LEARN: REJECTED class OTHER @ auth.hornbach.com: oauth/device + oauth/default + logi/srv + pub/src + user-srv + pub/auth with varying params all 404 — No socratic prom
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 23:40 UTC, 8th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 23:40 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth

## RANKED HYPOTHESES 2026-09-06 11:22:06 UTC
- [40] api.hornbach.de/healthcheck: SAP APIM Host-header backend probe leaks internal routing/healthcheck data (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: `GET https://api.hornbach.de/healthcheck` (passive, re-confirm Host→localhost:8080 backend leak) and `GET https://api.hornbach.de/api/version`-style vari
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: continue to confirm SAP APIM Gateway (Server: Gateway, X-CorrelationID) with 404 JSON root and Host-header backend l

## RANKED HYPOTHESES 2026-09-06 14:41:37 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- [50] api.hornbach.de: SSRF to localhost:8080 backend via SAP API Gateway route manipulation (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 09-05 23:40 UTC, 8th independent sess
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 09-05 23:40 UTC, stable; text/plain response body (not 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: Host/X-Forwarded-Host tampering on /healthcheck yields only 503 (modified Host) or the default localhost:8080 backen
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: re-confirmed SAP APIM Gateway (Via sapigwprd01/sapigwprd02, Server: Gateway, X-CorrelationID) backend on localhost:8
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 8th independent session; GET/HEAD ret
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable; text/plain response body (not JSON)
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: continue to confirm SAP APIM Gateway (Server: Gateway, X-CorrelationID) with 404 JSON root and Host-header backend l

## RANKED HYPOTHESES 2026-09-06 17:40:53 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` → client_id + redirect_uri scheme. Unlocks the 85-conf intro
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — systemic and stable across 8+ sessions;
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain response body; GET/HEAD returning 404 w
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)

## RANKED HYPOTHESES 2026-09-06 19:37:59 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` (or `res/values`/strings) → client_id + redirect_uri scheme.
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 8th independent session; GET/HEAD ret
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable; text/plain response body (not JSON)
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: continue to confirm SAP APIM Gateway (Server: Gateway, X-CorrelationID) with 404 JSON root and Host-header backend l

## RANKED HYPOTHESES 2026-09-06 21:45:07 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` → client_id + redirect_uri scheme. Unlocks the 85-conf intro
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 8th independent session; GET/HEAD ret
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable; text/plain response body (not JSON)
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: continue to confirm SAP APIM Gateway (Server: Gateway, X-CorrelationID) with 404 JSON root and Host-header backend l
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)

## RANKED HYPOTHESES 2026-09-06 23:38:37 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: REJECTED class AUTH @ auth.hornbach.com/apps-srv/clients/register: POST returns 404 — unauthenticated dynamic client registration (RFC 7591) not enabled
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
- LEARN: REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class AUTH @ auth.hornbach.de: Citrix NetScaler AAA VPN Gateway v25.5.1.15 confirmed (legacy employee access); EPA/VPN binaries downloadable
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 8th independent session; GET/HEAD ret
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable; text/plain response body (not JSON)
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: continue to confirm SAP APIM Gateway (Server: Gateway, X-CorrelationID) with 404 JSON root and Host-header backend l
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)

## RANKED HYPOTHESES 2026-09-07 01:21:14 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` → client_id + redirect_uri scheme. Unlocks the 85-conf intro
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 9th session; GET/HEAD returning 404 w
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable text/plain response; GET/HEAD returning 404 was 
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 8th independent session; GET/HEAD ret
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable; text/plain response body (not JSON)
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-07 06:14:58 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` → client_id + redirect_uri scheme. Unlocks the 85-conf intro
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download HORNBACH mobile app (de.hornbach) APK from APKMirror/Google Play, extract OAuth config (client_id + redirect_uri scheme) from assets/cidaas.xml 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 9th session; GET/HEAD returning 404 w
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable text/plain response; GET/HEAD returning 404 was 
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-07 12:52:49 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` → client_id + redirect_uri scheme. Unlocks the 85-conf intro
- NEXT(hypotheses-nemotron3.txt): PROBE: POST https://auth.hornbach.com/token-srv/introspect -H "Content-Type: application/x-www-form-urlencoded" -d "token=<dummy>" — confirm POST method returns
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 9th+ session; GET/HEAD returning 404 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable text/plain response; GET/HEAD returning 404 was 
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 9th session; GET/HEAD returning 404 w
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable text/plain response; GET/HEAD returning 404 was 
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-07 18:14:16 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` → client_id + redirect_uri scheme. Unlocks the 85-conf intro
- NEXT(hypotheses-nemotron3.txt): PROBE: POST https://auth.hornbach.com/token-srv/introspect -H "Content-Type: application/x-www-form-urlencoded" -d "token=dummy_test_token" — confirm POST metho
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 9th+ session; GET/HEAD returning 404 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable text/plain response; GET/HEAD returning 404 was 
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 10th session 18:13Z; GET/HEAD 404 was
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 10th session 18:13Z; stable text/plain; parameter-sensi
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:5
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo 
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: 10 paths today (root, health, api/v1, api/v2, odata, sap/opu/odata, sap/public/ping, iFlow, integration, monitoring) all
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 9th+ session; GET/HEAD returning 404 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable text/plain response; GET/HEAD returning 404 was 
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: authorization endpoint live with verbose error messages; redirect_uri validation testing requires valid
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: SAP API Gateway exists (Gateway server header) with backend on localhost:8080; no documented endpoints at common paths
- LEARN: ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is in-scope API surface; all /api/* require Mirakl auth
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 `{"status":"OK","updatedAt"}` — discovery status endpoint live and stable
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-07 21:38:18 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- [70] auth.hornbach.com/authz-srv/authz: OAuth redirect_uri validation bypass via regex/wildcard mismatch (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` → client_id + redirect_uri scheme. Unlocks the 85-conf intro
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` → client_id + redirect_uri scheme. Unlocks the 85-conf intro
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 10th session 18:13Z; GET/HEAD 404 was
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 10th session 18:13Z; stable text/plain; parameter-sensi
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:5
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo 
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: 10 paths today (root, health, api/v1, api/v2, odata, sap/opu/odata, sap/public/ping, iFlow, integration, monitoring) all
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 9th+ session; GET/HEAD returning 404 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — stable text/plain response; GET/HEAD returning 404 was 
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:5
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo 
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: 10 paths today (root, health, api/v1, api/v2, odata, sap/opu/odata, sap/public/ping, iFlow, integration, monitoring) all
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know

## RANKED HYPOTHESES 2026-09-07 23:49:07 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` (APKPure v3.9.0 or AppBrain v2.9.2, `de.hornbach.app.smarthome`), extract `assets/cidaas.xml` → client_id + redirect
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal), extract `assets/cidaas.xml` → client_id + redirect_uri scheme. Unlocks the 85-conf intro
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 10th session 18:13Z; GET/HEAD 404 was
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 10th session 18:13Z; stable text/plain; parameter-sensi
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:5
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo 
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: 10 paths today (root, health, api/v1, api/v2, odata, sap/opu/odata, sap/public/ping, iFlow, integration, monitoring) all
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know

## RANKED HYPOTHESES 2026-09-08 03:54:37 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKPure v3.9.0 or AppBrain v2.9.2, package `de.hornbach.app.smarthome`), extract `assets/cidaas.xml` → client_i
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal/APKPure v3.9.0 or AppBrain v2.9.2), extract `assets/cidaas.xml` → client_id + redirect_uri
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 10th session 18:13Z; GET/HEAD 404 was m
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 10th session 18:13Z; stable text/plain; parameter-sensiti
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:5
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo 
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: 10 paths today (root, health, api/v1, api/v2, odata, sap/opu/odata, sap/public/ping, iFlow, integration, monitoring) all
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 10th session 18:13Z; GET/HEAD 404 was
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 10th session 18:13Z; stable text/plain; parameter-sensi
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:5
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know

## RANKED HYPOTHESES 2026-09-08 08:49:28 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKPure v3.9.0 or AppBrain v2.9.2, package `de.hornbach.app.smarthome`), extract `assets/cidaas.xml` → client_i
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal/APKPure v3.9.0 or AppBrain v2.9.2, package `de.hornbach.app.smarthome`), extract `assets/c
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 10th session 18:13Z; GET/HEAD 404 was m
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 10th session 18:13Z; stable text/plain; parameter-sensiti
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:5
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo 
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: 10 paths today (root, health, api/v1, api/v2, odata, sap/opu/odata, sap/public/ping, iFlow, integration, monitoring) all
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 10th session 18:13Z; GET/HEAD 404 was
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 10th session 18:13Z; stable text/plain; parameter-sensi
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:5
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know

## RANKED HYPOTHESES 2026-09-08 13:30:46 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: APK extraction (sole unblocker).
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal/APKPure v3.9.0 or AppBrain v2.9.2, package `de.hornbach.app.smarthome`), extract `assets/c
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 13:27Z 11th session; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 `{"success":false,"status":500}` + Access-Control-Allow-Origin:*; POST → 404 (GET
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 10th session 18:13Z; GET/HEAD 404 was
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 10th session 18:13Z; stable text/plain; parameter-sensi
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 18:13Z — 302→AUTH10007 invalid_client on dummy client_id; REJECTS the 2026-09-06-16:5
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/users-srv/userinfo: mounted, anonymous 401 JSON bearer-gated; token-srv/userinfo → 404 router-doesn't-exist — userinfo 
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact (06:30Z) — all 6 service endpoints + status advertised; REJ
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: GET with grant_type → 400 `invalid_client` (client required); token plane client-gated, isolating the u
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: discovery advertises `token-exchange`(RFC 8693), `password`, `client_credentials` grants + `subject_types_supported=["
- LEARN: ACCEPTED class MISCONFIG @ api.hornbach.de: 8 additional paths tested (graphql, api/graphql, v1/graphql, openapi.json, swagger.json, api-docs, sap/apigateway, s
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules (OPTIONS/TRACE excluded from scope)
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id enumeration via status-code differential is REMOVED — invalid client_ids return uniform 302→A
- LEARN: REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates
- LEARN: REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 know

## RANKED HYPOTHESES 2026-09-08 17:33:24 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKPure v3.9.0 or AppBrain v2.9.2, package `de.hornbach.app.smarthome`), extract `assets/cidaas.xml` → client_i
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal/APKPure v3.9.0 or AppBrain v2.9.2, package `de.hornbach.app.smarthome`), extract `assets/c
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 11th session 13:27Z; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 `{"success":false,"status":500}` + Access-Control-Allow-Origin:*; POST → 404 (GET
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 13:27Z 11th session; systemic and sta
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 `{"success":false,"status":500}` + Access-Control-Allow-Origin:*; POST → 404 (GET
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-08 20:19:01 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal/APKPure v3.9.0 or AppBrain v2.9.2, package `de.hornbach.app.smarthome`), extract `assets/c
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 13:27Z 11th session; systemic and sta
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 `OK` unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 `{"success":false,"status":500}` + Access-Control-Allow-Origin:*; POST → 404 (GET
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-08 22:50:56 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal/APKPure v3.9.0 or AppBrain v2.9.2, package `de.hornbach.app.smarthome`), extract `assets/c
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 13:27Z 11th session; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-09 01:17:49 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: POC: valid token introspect → claim disclosure, revoke → silent session kill (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` (APKMirror/APKPure/AppBrain; current APK v3.9.0, mSun 2.9.2, pkg `de.hornbach.app.smarthome`), unzip, copy out `asse
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/VirusTotal/APKPure v3.9.0 or AppBrain v2.9.2, package `de.hornbach.app.smarthome`), extract `assets/c
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 11th session 13:27Z; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-09 06:13:02 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- [85] auth.hornbach.com/token-srv/introspect: Unauthenticated token introspection enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current APK v3.9.0, mSun 2.9.2, pkg `de.hornbach.app.smarthome`), unzip, copy out `
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 11th session 13:27Z; systemic and sta
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 `{"success":false,"status":500}` + Access-Control-Allow-Origin:*; POST → 404 (GET
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 11th session 13:27Z; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-09 11:46:39 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 11th session 13:27Z; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-09 15:26:03 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: systemic unauthenticated POST → 200 across 11+ sessions; GET/HEAD 404 was methodology artefact
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: stable unauthenticated POST → 200 OK text/plain; GET/HEAD parameter-sensitive 404
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: LIVE uniform gate; client_id enumeration REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 11th session 13:27Z; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-09 18:46:37 UTC
- [85] de.hornbach.app.smarthome: Cross-check: Hornbach Smarthome app leaks cidaas client_id + redirect_uri scheme (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Obtain a valid cidaas client_id — the sole gate across all three FINAL chains. Revised priority: (1) capture `client_id` from the `/authz-srv/authz` redi
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com: GET-plane recheck 09-09 — OIDC discovery 200/3189B, authz uniform 302→AUTH10007, api.hornbach.de root 404/47B; all core
- LEARN: ACCEPTED class MISCONFIG @ smarthomebyhornbach.com: 09-09 scan — 5 live CDN SPA shells all common paths uniform 404 (215B), api-gw-evvr Zscaler edge TLS-fail, d
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 11th session 13:27Z; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-09 21:36:15 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 11th session 13:27Z; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-09 23:34:33 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Obtain a valid cidaas client_id — still the sole unblocker for both FINAL chains. Repeat-first priority (a): open a fresh browser, hit `https://auth.horn
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com: GET-plane recheck ~23:2xZ 09-09 — discovery 200/3189B, status 200/60B, authz uniform 302→AUTH10007, api.hornbach.de 404
- LEARN: ACCEPTED class OTHER @ smarthomebyhornbach.com: unreachable (code=000) from this egress — consistent with prior api-gw-evvr Zscaler TLS-fail; no additive surfac
- LEARN: REJECTED class OTHER @ github.com/hornbach: 0 public repos; public-repo client_id grep exhausted (KB 09-09 02:33Z).

## RANKED HYPOTHESES 2026-09-10 01:31:59 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Obtain a valid cidaas `client_id` — sole unblocker for both FINAL chains. Passive web paths are exhausted (confirmed this session: login.hornbach.com red
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 11th session 13:27Z; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 11th session 13:27Z; systemic and stabl
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-10 06:46:13 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: GET https://auth.hornbach.com/ → save full HTML (3038 bytes) → grep for client_id / ClientId / client-id / cidaas config objects / JS bundle URLs; if JS 
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 12th session 01:29Z 09-10; systemic and
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 11th session 13:27Z; systemic and sta
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — 11th session; stable text/plain
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE 13:27Z — 302→AUTH10007 invalid_client on dummy client_id; uniform gate, client_id enu
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET still 500 {"success":false,"status":500} + Access-Control-Allow-Origin:*; POST → 404 (GET-o
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: requires access_token_hint/id_token_hint (302→AATON1018), client/token-gated — no anonymous lo
- LEARN: ACCEPTED class OTHER @ hornbach-mp.mirakl.net: root→/login/oauth2/mirakl-sso→login.mirakl.net (platform IdP, client_id UNPB4KbSz10ZExFyRsNQ6JHbKBeW94nq, PKCE S2
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE in Allow header is REJECTED class per scope rules
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed — 302→logon closes NetScaler management API; requires authenticated session

## RANKED HYPOTHESES 2026-09-10 12:06:57 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: GET https://auth.hornbach.com/ → save full HTML (3038 bytes) → grep for client_id / ClientId / client-id / cidaas config objects / JS bundle URLs; if JS 
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 12th session 01:29Z 09-10; systemic and
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-10 16:16:28 UTC
- [65] auth.hornbach.com/authz-srv/authz: OAuth redirect_uri validation bypass via regex/wildcard mismatch on authz-srv/authz (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 12th session 01:29Z 09-10; systemic and
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-10 19:11:18 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables silent session kill + metadata leak (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: REJECTED class OTHER @ auth.hornbach.com/ (root): root HTML is F5/Shape Security bot-challenge shell (_fs-ch-* prefix, Client Challenge title), NOT cidaas login
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 12th session 01:29Z 09-10; systemic and
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 12th session 01:29Z 09-10; systemic a
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-10 21:46:49 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 12th session 01:29Z 09-10; systemic a
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-10 23:53:47 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 12th session 01:29Z 09-10; systemic a
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-11 03:52:49 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- [65] auth.hornbach.com/: auth.hornbach.com root HTML page embeds cidaas client_id in JavaScript configuration (from art/lead_bigpickle.txt)
- NEXT(hypotheses-bigpickle.txt): PROBE: GET https://auth.hornbach.com/ → save full HTML (3038 bytes) → grep for client_id / ClientId / client-id / cidaas config objects / JS bundle URLs; if JS 
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 12th session 01:29Z 09-10; systemic and
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 12th session 01:29Z 09-10; systemic and
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed
- LEARN: REJECTED class OTHER @ auth.hornbach.com/ (root): root HTML is F5/Shape Security bot-challenge shell (_fs-ch-* prefix, Client Challenge title), NOT cidaas login
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 {"active":false} unauthenticated — 12th session 01:29Z 09-10; systemic and
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 13th session 09-11; b
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 12th session 01:29Z 09-10; systemic a
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-11 08:49:14 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` AND the `de.hornbach.*`/`com.hornbach.*` retail app APK via browser-authenticated Play Store or un-walled mirror; un
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14th session 08:47Z 0
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 OK — discovery status endpoint live
- LEARN: CHANGED class OTHER @ auth.hornbach.com/ (root): now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend but no conten
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: RE-CONFIRMED POST → 200 `{"active":false}` unauthenticated — 12th session 01:29Z 09-10; systemic a
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: RE-CONFIRMED POST → 200 OK unauthenticated — stable text/plain; parameter-sensitive 404 on GET/HEAD
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume

## RANKED HYPOTHESES 2026-09-11 13:35:17 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14th session 08:47Z 0
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 OK — discovery status endpoint live
- LEARN: CHANGED class OTHER @ auth.hornbach.com/ (root): now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend but no conten
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-11 17:24:11 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- [65] auth.hornbach.com/authz-srv/authz: OAuth redirect_uri validation bypass via regex/wildcard mismatch on authz-srv/authz (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK via Play Store device capture or un-walled mirror; unzip; grep `assets/cidaas*.xml`, `assets/config*.json`, `*.p
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: 2 novel SAP ICM paths (/sap/bc/ping, /sap/wdisp/admin/public/default/cluster) → uniform 404 len=47; Via shows sapigwprd0
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14+ sessions; systemi
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: estate-wide F5 bot-challenge; no web-based client_id extraction
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14th session 08:47Z 0
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 OK — discovery status endpoint live
- LEARN: CHANGED class OTHER @ auth.hornbach.com/ (root): now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend but no conten
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-11 19:57:09 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection/revocation enables claim-set disclosure + silent session kill (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0 plus any `de.hornbach.*`/`com.hornbach.*` retail app), unzip, then (
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class OTHER @ api.hornbach.de: 19:50Z re-confirm — root 404/47B, /healthcheck 200 xml with Host: localhost:8080 backend leak, Via sapigwprd01 (both hop
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com: root 302→hornbach.de unchanged at 19:5xZ — stable across 08:47Z/13:31Z/19:5xZ; no client_id exposure in redirect/heade
- LEARN: ACCEPTED class OTHER @ smarthomebyhornbach.com: DNS NXDOMAIN for full/apex from this egress — consistent with prior code=000; no additive surface assertion.
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14th session 08:47Z 0
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 OK — discovery status endpoint live
- LEARN: CHANGED class OTHER @ auth.hornbach.com/ (root): now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend but no conten
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-11 22:24:48 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- [0] N/A: No findings (from art/lead_bigpickle.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14th session 08:47Z 0
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 OK — discovery status endpoint live
- LEARN: CHANGED class OTHER @ auth.hornbach.com/ (root): now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend but no conten
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-12 00:44:17 UTC
- [85] https://auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables claim-set disclosure and silent session kill (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure, current v3.9.0, plus any `de.hornbach.*`/`com.hornbach.*` retail app); unzip; (1) grep `asse
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14th session 08:47Z 0
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 OK — discovery status endpoint live
- LEARN: CHANGED class OTHER @ auth.hornbach.com/ (root): now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend but no conten
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-12 05:05:12 UTC
- [85] https://auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables claim-set disclosure and silent session kill (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure, current v3.9.0, plus any `de.hornbach.*`/`com.hornbach.*` retail app); unzip; (1) grep `asse
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14th session 08:47Z 0
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 OK — discovery status endpoint live
- LEARN: CHANGED class OTHER @ auth.hornbach.com/ (root): now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend but no conten
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-12 09:29:55 UTC
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14th session 08:47Z 0
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 OK — discovery status endpoint live
- LEARN: CHANGED class OTHER @ auth.hornbach.com/ (root): now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend but no conten
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed

## RANKED HYPOTHESES 2026-09-12 13:12:28 UTC
- [85] https://auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables claim-set disclosure and silent session kill (from art/lead_bigpickle.txt)
- [85] auth.hornbach.com/token-srv/{introspect,revoke}: Unauthenticated token introspection + revocation enables silent session kill + metadata leak (from art/lead_nemotron3.txt)
- NEXT(hypotheses-bigpickle.txt): HUMAN: obtain a valid cidaas client_id for `auth.hornbach.com` via (a) `de.hornbach.app.smarthome` APK from a non-bot-filtered source/device (apkpure/apkmirror 
- NEXT(hypotheses-nemotron3.txt): HUMAN: Download `de.hornbach.app.smarthome` APK (APKMirror/APKPure/AppBrain; current v3.9.0, package `de.hornbach.app.smarthome`), unzip, extract `assets/cidaas
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/{introspect,revoke}: RE-CONFIRMED POST → 200 {"active":false} / 200 OK unauthenticated — 14th session 08:47Z 0
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/openid-configuration: RE-CONFIRMED fully intact 3189B — all 6 service endpoints + status advertised
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/.well-known/status: 200 OK — discovery status endpoint live
- LEARN: CHANGED class OTHER @ auth.hornbach.com/ (root): now returns 302 → hornbach.de (was 200 len=3038 F5 challenge); CSP header confirms cidaas backend but no conten
- LEARN: ACCEPTED class AUTH @ auth.hornbach.com/token-srv/token: POST authorization_code + bogus client → 400 invalid_client "unknown client" — token plane client-gated
- LEARN: REJECTED class OATH @ auth.hornbach.com/authz-srv/authz: client_id discrepancy (invalid_client vs invalid_grant) is unactionable with zero candidate seed; enume
- LEARN: ACCEPTED class OTHER @ hornbach.com web estate: international TLDs (at/nl/ch) + de + login all serve identical 3038-byte F5 "Client Challenge" stub — estate-wid
- LEARN: ACCEPTED class OATH @ auth.hornbach.com/authz-srv/authz: RE-CONFIRMED LIVE — 302→AUTH10007 uniform gate; client_id enum REMOVED
- LEARN: ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: GET 500 + CORS wildcard; POST 404
- LEARN: REJECTED class MISCONFIG @ auth.hornbach.com/session/end_session: token-gated, no anonymous CSRF
- LEARN: REJECTED class MISCONFIG @ api.hornbach.de: OPTIONS/TRACE excluded per scope
- LEARN: REJECTED class AUTH @ auth.hornbach.de: /nitro/v1/config NOT exposed
