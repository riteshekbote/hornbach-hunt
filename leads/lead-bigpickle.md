## 2026-09-03 17:13:58 UTC [target] (model bigpickle)
[PRIO] auth.hornbach.com, 8.2, attack_surface:9, business_value:9, tech_exposure:8, gate_ease:7, cloud_surface:8, freshness:8
[PRIO] login.hornbach.com, 7.0, attack_surface:7, business_value:8, tech_exposure:6, gate_ease:7, cloud_surface:6, freshness:8
[PRIO] www.hornbach.com, 5.5, attack_surface:5, business_value:7, tech_exposure:4, gate_ease:6, cloud_surface:5, freshness:8
[HYP] cidaas OAuth redirect_uri validation bypass
class: OATH
asset: auth.hornbach.com
confidence: 35
reasoning: auth.hornbach.com is CNAME to hornbach-prod.cidaas.eu (third-party IdP); cidaas supports OAuth2/OIDC flows; redirect_uri parameter validation is a common misconfiguration point in hosted IdP integrations; no explicit redirect_uri whitelist testing has been performed yet
evidence_needed: capture OAuth authorize request parameters, enumerate valid redirect_uri values via passive observation
verify_steps: GET https://auth.hornbach.com/ → follow 302 to hornbach.de; observe query params (client_id, redirect_uri, state); attempt parameter pollution with non-hornbach redirect_uri values; test with curl --max-redirs 0 -v
impact: OAuth code theft → account takeover; severity HIGH if redirect_uri is loosely validated
testability: PASSIVE
[PARKED] cidaas OAuth redirect_uri validation bypass: confidence 35 < 40 threshold; no OAuth flow captured yet to confirm redirect_uri parameter exists or is user-controlled; cidaas is a mature provider likely to have strict defaults
[NEXT] PROBE: GET https://auth.hornbach.com/ -v --max-redirs 0 to capture initial redirect chain and query parameters (client_id, redirect_uri, state) for OAuth flow analysis
[LEARN] REJECTED class WILDCARD_DOM: wildcard DNS dominates hornbach.com zone; no dedicated hosts recovered; move to CDN-proxied surface analysis instead of subdomain enumeration
[LEARN] ACCEPTED class OATH: third-party IdP (cidaas) integration on auth.hornbach.com creates OAuth/OIDC attack surface worth investigating
[RISK] hornbach: 25/100; broad scope with CDN-heavy architecture limits direct infrastructure access; private disclosure channel (bugs.olivermaicher.eu) indicates responsive program; cidaas is mature third-party provider reducing misconfiguration likelihood; surface is limited to 4 hosts with 2 live HTTP endpoints
## 2026-09-03 19:57:55 UTC [target] (model bigpickle)
[CHANGED] auth.hornbach.com: OIDC discovery endpoint `.well-known/openid-configuration` returns 200 with full provider metadata; 6 new service endpoints discovered (authz-srv, token-srv, users-srv, apps-srv, user-scim-srv, token-srv/introspect)
[CHANGED] auth.hornbach.com: Authorization endpoint `authz-srv/authz` confirmed live — returns 302 to error page with `invalid_client` + verbose error_description + error_hint
[CHANGED] auth.hornbach.com: Device code flow endpoint `authz-srv/device/authz` confirmed live — returns 400 with JSON `invalid_request`
[CHANGED] auth.hornbach.com: JWKS endpoint `.well-known/jwks.json` returns 5+ RSA public keys (RS256)
[NEW] auth.hornbach.com: Client registration endpoint `apps-srv/clients/register` exists in OIDC metadata — returns 404 on GET, may accept POST (unauthenticated client registration potential)
[NEW] auth.hornbach.com: SCIM endpoint `user-scim-srv/v2` exists in OIDC metadata — returns 404 on GET, worth POST/fuzzing (user provisioning protocol)
[NEW] auth.hornbach.com: Introspection endpoint `token-srv/introspect` exposed in metadata
[CHANGED] www.hornbach.com / hornbach.de: Login page returns bot-challenge page (FingerprintJS-based `_fs_ch_st_` cookie), 3038-byte stub, not direct login form
[PRIO] auth.hornbach.com, 8.6, attack_surface:9, business_value:9, tech_exposure:9, gate_ease:7, cloud_surface:8, freshness:9
[PRIO] www.hornbach.com, 5.0, attack_surface:5, business_value:6, tech_exposure:3, gate_ease:6, cloud_surface:4, freshness:6
[PRIO] login.hornbach.com, 4.5, attack_surface:4, business_value:6, tech_exposure:3, gate_ease:5, cloud_surface:5, freshness:5
[HYP] Unauthenticated OAuth client registration via apps-srv/clients/register
class: AUTH
asset: auth.hornbach.com/apps-srv/clients/register
confidence: 55
reasoning: OIDC discovery metadata lists `registration_endpoint: https://auth.hornbach.com/apps-srv/clients/register`. Dynamic client registration (RFC 7591) allows creating OAuth clients without pre-provisioning. GET returns 404 "Not Found" but POST with JSON body returned 404 with content-length 9 — server may filter by method. If unauthenticated POST is accepted, attacker can register a client with arbitrary redirect_uri, enabling OAuth code theft. cidaas documentation (service_documentation: https://docs.cidaas.de/) confirms registration feature exists.
evidence_needed: POST to apps-srv/clients/register with Content-Type: application/json and {"client_name":"test","redirect_uris":["https://evil.com"]}; observe 201 vs 401/403 vs 404
verify_steps: curl -s -D- -X POST https://auth.hornbach.com/apps-srv/clients/register -H "Content-Type: application/json" -d '{"client_name":"test","redirect_uris":["https://evil.com"],"grant_types":["authorization_code"],"response_types":["code"]}'; check status code and response body
impact: Unauthenticated client registration → register attacker-controlled redirect_uri → steal OAuth authorization codes → account takeover; severity CRITICAL
testability: PASSIVE
[HYP] OAuth redirect_uri validation bypass on authz-srv/authz
class: OATH
asset: auth.hornbach.com/authz-srv/authz
confidence: 50
reasoning: Authorization endpoint confirmed live at authz-srv/authz; returns detailed error about invalid client_id; redirect_uri parameter accepted in request without immediate rejection (server validates client_id first). Once a valid client_id is found, redirect_uri validation becomes the next gate. cidaas as a CIAM platform may use regex/wildcard matching for redirect_uri allowlists. Path traversal (../), subdomain variation (.evil.com), or open redirect within hornbach.de could bypass strict matching.
evidence_needed: Find valid client_id (e.g. from hornbach.de frontend JS or login flow), then test redirect_uri variations: https://evil.com, https://hornbach.de.evil.com, https://hornbach.de@evil.com, https://hornbach.de/../../evil.com
verify_steps: 1) Inspect www.hornbach.de/customer/login page source and JS bundles for client_id values; 2) curl -s -D- "https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid" --max-redirs 0; 3) If redirected to login page (not error), test redirect_uri variations
impact: OAuth code theft → account takeover; severity HIGH
testability: AUTH_HELPED
[HYP] Device code flow social engineering via authz-srv/device/authz
class: AUTH
asset: auth.hornbach.com/authz-srv/device/authz
confidence: 45
reasoning: Device authorization endpoint confirmed live (returns 400 "invalid_request" with correct params expected). Device code flow (RFC 8628) generates a user_code + verification_uri pair that user must enter on their device. If attacker can initiate device code flow for a valid client_id and obtain a user_code, they can social-engineer victim into approving on their device, granting attacker session tokens. The verbose error messages suggest the endpoint validates request format but doesn't reject the flow outright.
evidence_needed: POST to authz-srv/device/authz with correct JSON params for device authorization; obtain user_code and verification_uri
verify_steps: curl -s -X POST https://auth.hornbach.com/authz-srv/device/authz -H "Content-Type: application/json" -d '{"client_id":"<valid_client_id>","scope":"openid"}'; check response for user_code, verification_uri, device_code
impact: Account takeover via social-engineered device code approval; severity HIGH
testability: AUTH_HELPED
[PARKED] Device code flow social engineering: confidence 45 < 50 threshold; requires valid client_id to initiate; social engineering element makes it less reliable for pure technical testing
[FINAL] 1. Unauthenticated OAuth client registration (confidence 55, PASSIVE, CRITICAL if confirmed)
[FINAL] 2. OAuth redirect_uri validation bypass (confidence 50, AUTH_HELPED, HIGH)
[FINAL] 3. Device code flow abuse (confidence 45, AUTH_HELPED, HIGH) — PARKED but monitored
[NEXT] PROBE: curl -s -D- -X POST https://auth.hornbach.com/apps-srv/clients/register -H "Content-Type: application/json" -d '{"client_name":"test_probe","redirect_uris":["https://evil.com"],"grant_types":["authorization_code"],"response_types":["code"]}' — test if unauthenticated client registration is accepted
[LEARN] ACCEPTED class AUTH: cidaas CIAM platform on auth.hornbach.com exposes full OIDC provider metadata including registration_endpoint, device_authorization_endpoint, introspection_endpoint, and SCIM endpoint — broader attack surface than initially assessed
[LEARN] ACCEPTED class OATH: Authorization endpoint confirmed live at authz-srv/authz with verbose error messages; redirect_uri validation testing requires valid client_id discovery first
[RISK] hornbach: 45/100; OIDC discovery fully exposed revealing complete auth infrastructure with 6+ service endpoints; registration_endpoint exists in metadata (RFC 7591 dynamic client registration); device_code flow supported; verbose error messages aid enumeration; but cidaas is mature CIAM with likely strict defaults; surface still limited to auth.hornbach.com with bot-protected www.hornbach.de fronting actual login flow; 4 hosts total with wildcard DNS limiting subdomain discovery
## 2026-09-03 22:29:03 UTC [target] (model bigpickle)
