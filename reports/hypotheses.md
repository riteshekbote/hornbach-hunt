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
