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
## 2026-09-04 00:27:17 UTC [target] (model bigpickle)
## 2026-09-04 05:12:30 UTC [target] (model bigpickle)
[HYP] Unauthenticated token introspection — probing for data exposure via /token-srv/introspect
class: AUTH
asset: auth.hornbach.com/token-srv/introspect
confidence: 45
reasoning: /token-srv/introspect accepts POST with token param and returns {"active":false} (HTTP 200) WITHOUT client authentication. RFC 7662 requires client auth; cidaas metadata lists introspection_endpoint_auth_methods but the live endpoint did not enforce it on the test. If valid tokens can be introspected unauthenticated, it may leak token metadata (sub, scope, exp) equivalent to an authz data leak.
evidence_needed: obtain a real access token (requires valid client_id + login) OR a leaked token; however unauthenticated acceptance of introspection is itself abnormal
verify_steps: (PASSIVE) repeat GET/POST variant probing; note 200-application/json vs 404-router; requires valid token to prove data-exfiltration impact
impact: potential token-metadata disclosure if real tokens accepted without client auth; severity MEDIUM (unconfirmed)
testability: AUTH_HELPED (needs token)
[HYP] cidaas OIDC JWT alg confusion (HS256/RS256)
class: AUTH
asset: auth.hornbach.com/.well-known/openid-configuration
confidence: 40
reasoning: OIDC metadata lists id_token_signing_alg_values_supported: [HS256, RS256] AND token_endpoint_auth_signing_alg_values_supported: [HS256, RS256]. If any endpoint accepts HS256 for id_tokens using the RS256 public key (from /well-known/jwks.json) as the HMAC secret, an attacker forges tokens. However cidaas is mature and likely pins per-client alg; needs valid client_id + token capture to test.
evidence_needed: valid client_id, capture a legit id_token, attempt HS256-forged variant
verify_steps: after obtaining client_id+token, request token endpoint with alg=HS256 compromised via known pubkey
impact: token forgery → full account impersonation; severity CRITICAL
testability: AUTH_HELPED (blocked by no client_id)
[PARKED] Unauthenticated OAuth client registration @ apps-srv/clients/register: confidence 40 — 404 on ALL methods incl. properly-formed POST; registration clearly disabled at routing; no longer a viable vector
[PARKED] OAuth redirect_uri validation bypass: confidence 50 but requires valid client_id discovery; all ~40 guessed client_ids rejected; bot-challenge blocks the source (www) where client_id would be embedded; blocked on client_id
[PARKED] cidaas JWT alg confusion: confidence 40 < 45 — blocked on client_id + token capture; mature provider likelihood of strict per-client config
[PARKED] Unauthenticated introspection: needs real token to prove impact; unauthenticated acceptance without a real token proves nothing
[NEXT] PROBE: enumerate a valid cidaas client_id from the HORNBACH mobile app (de.hornbach) by obtaining/parsing its OAuth config (client_id + redirect_uri) — required to unblock all OAuth hypotheses; if app unobtainable, test google/ios deep-link callback patterns on authz-srv/authz with a candidate (e.g. redirect_uri=de.hornbach:// or app://callback with guessed client_ids from app package)
[LEARN] REJECTED class MISCONFIG @ auth.hornbach.com: dynamic OAuth client registration disabled — /apps-srv/clients/register 404 on all methods; metadata endpoint exists but routing is blocked
[LEARN] ACCEPTED class AUTH @ auth.hornbach.de: separate Citrix NetScaler AAA VPN Gateway surface exists on hornbach.de, distinct from cidaas .com — legacy employee access infra in-scope
[LEARN] ACCEPTED class MISCONFIG @ hornbach-mp.mirakl.net: HORNBACH-operated Mirakl marketplace (v3.1301) is an in-scope API surface; all /api/* require Mirakl auth
[LEARN] REJECTED class WILDCARD_DOM @ hornbach.com: no wildcard DNS (random-xyz-test returns empty) — contradicts prior KB "wildcard dominates" conclusions; only 4 known scoped hosts resolve
[RISK] hornbach: 42/100 — cidaas tenant is the confirmed live auth surface with OIDC metadata exposing full endpoint map; dynamic client registration disabled; valid client_id remains the critical unlock gating all OAuth testing (redirect_uri, alg confusion, code theft); new legacy NetScaler AAA on auth.hornbach.de broadens employee-auth surface but is high-risk to probe; www.hornbach.de bot-walled (FingerprintJS) blocks the source that would embed the client_id; Mirakl marketplace (hornbach-mp) is a separate auth'd API surface; broad scope but CDN-heavy and gate-hard.
[PRIO] auth.hornbach.com, 8.6, attack_surface:9,business_value:9,tech_exposure:9,gate_ease:7,cloud_surface:8,freshness:9
[PRIO] auth.hornbach.de, 6.4, attack_surface:6,business_value:7,tech_exposure:8,gate_ease:5,cloud_surface:4,freshness:8
[PRIO] hornbach-mp.mirakl.net, 5.5, attack_surface:6,business_value:6,tech_exposure:6,gate_ease:3,cloud_surface:5,freshness:7
[HYP] Unauthenticated token introspection on /token-srv/introspect
class: AUTH
asset: auth.hornbach.com/token-srv/introspect
confidence: 45
reasoning: /token-srv/introspect returns HTTP 200 {"active":false} for POST token=fake WITHOUT any client authentication, though introspect_endpoint_auth_methods requires client_secret/private_key_jwt. Unauthenticated acceptance of the introspection router is abnormal (RFC 7662 requires auth); if any valid token is introspected it may leak sub/scope/exp metadata.
evidence_needed: a valid access_token to introspect (needs client_id+login) to prove metadata exfiltration
verify_steps: repeat unauthenticated POST with varied token params; requires real token to demonstrate impact
impact: token metadata / active-session disclosure; severity MEDIUM (unconfirmed)
testability: AUTH_HELPED
[HYP] cidaas OIDC JWT algorithm confusion (HS256/RS256)
class: AUTH
asset: auth.hornbach.com (token-srv / users-srv)
confidence: 40
reasoning: OIDC metadata lists id_token_signing_alg_values_supported [HS256,RS256] and token_endpoint_auth_signing_alg_values_supported [HS256,RS256]. If any token endpoint accepts HS256 with the RS256 public key (from /well-known/jwks.json) as HMAC secret, tokens can be forged. Requires a valid client_id + captured token to test; cidaas is mature so per-client alg is likely pinned.
evidence_needed: valid client_id; a legit id_token; test HS256-forged variant against token/userinfo endpoints
verify_steps: after client_id+token obtained, submit alg=HS256 token signed with pubkey-derived secret to userinfo_signing and observe 200 vs 401
impact: token forgery → full account impersonation; severity CRITICAL
testability: AUTH_HELPED
[NEXT] PROBE: obtain a valid cidaas client_id by parsing the HORNBACH mobile app (de.hornbach) OAuth config; fallback: test candidate redirect_uris (de.hornbach://callback, app://callback) + app package-name-derived client_ids against /authz-srv/authz to find a live client, which unblocks all parked OAuth hypotheses
[RISK] hornbach: 42/100 — cidaas tenant is confirmed live auth surface, OIDC metadata fully exposed; client registration disabled; valid client_id is the critical unlock gating all OAuth testing (redirect_uri, alg confusion, code theft, device code); new legacy NetScaler AAA on auth.hornbach.de broadens employee-auth surface but is high-risk to probe (employee/infra); www.hornbach.de bot-walled (FingerprintJS) blocks the source embedding client_id; hornbach-mp.mirakl.net is a separate auth-gated Mirakl API surface; broad scope but CDN-heavy and gate-hard.
## 2026-09-04 09:57:53 UTC [target] (model bigpickle)
[HYP] Unauthenticated token introspection leaks token metadata
class: AUTH
asset: auth.hornbach.com/token-srv/introspect
confidence: 50
reasoning: POST to /token-srv/introspect with `token=fake` returns HTTP 200 `{"active":false}` without ANY client authentication (no Basic auth, no client_secret, no client_assertion). RFC 7662 §2.1 requires resource server to authenticate itself; cidaas metadata lists `introspection_endpoint_auth_methods_supported`. Unauthenticated acceptance is a concrete misconfiguration — if valid tokens are accepted, attacker gets sub/scope/exp/token_type metadata for any access token without credentials.
evidence_needed: valid access_token from cidaas (requires client_id + user login) to prove data exfiltration; the unauthenticated acceptance itself is the misconfiguration
verify_steps: (DONE) POST with fake token returns 200; NEXT: obtain real token from mobile app flow, introspect unauthenticated, verify response contains token metadata (sub, scope, exp, client_id)
impact: token metadata disclosure (active sessions, scopes, user identity, expiry); severity MEDIUM; chain potential: introspect stolen/leaked tokens to map session state
testability: AUTH_HELPED (needs valid client_id + user login to obtain token)
[HYP] api.hornbach.de internal hostname disclosure via Via header
class: MISCONFIG
asset: api.hornbach.de
confidence: 55
reasoning: Via response header leaks `Via: 1.0 sapigwprd01 (Gateway), 1.0 sapigwprd01 (Gateway)` — reveals internal SAP API Gateway hostname and software. Combined with `/healthcheck` returning 200 XML `<status>ok</status>` with `Host: localhost:8080` in response, this confirms SAP APIM backend on localhost:8080 behind the gateway. Gateway also returns structured JSON error messages with X-CorrelationID for request tracing.
evidence_needed: already confirmed via passive probing
verify_steps: (DONE) GET /healthcheck returns 200 with Via header leak; impact is information disclosure
impact: internal hostname + software fingerprinting enables targeted attacks against SAP APIM; severity LOW; but if path discovery yields API endpoints, combined with gateway bypass could lead to backend access
testability: PASSIVE
[HYP] Citrix NetScaler version exposure + downloadable EPA/VPN binaries
class: MISCONFIG
asset: auth.hornbach.de
confidence: 45
reasoning: Citrix NetScaler Gateway v25.5.1.15 fully exposed: pluginlist.xml reveals exact versions (NS 25.5.1.15, Opswat EPA 4.3.4619.0/4.3.2138.0); EPA/VPN installer binaries are publicly downloadable (HTTP 200): nsepa_setup.exe, epaPackage.exe, Citrix_Endpoint_Analysis.dmg, MacLibs.zip. gwtest.jsp returns HTTP 500 with internal error code 43549. This is employee-facing VPN infrastructure — may have separate vuln class vs cidaas.
evidence_needed: confirmed via passive probing; version 25.5.1.15 maps to Citrix NetScaler ADC — check for CVE-2023-4966 (Citrix Bleed), CVE-2024-6235, CVE-2025-6543 etc; current version likely patched for known CVEs but surface is worth monitoring
verify_steps: (DONE) pluginlist.xml returns full version info; EPA binaries downloadable; gwtest.jsp 500; NEXT: check if version 25.5.1.15 is current/latest or if any unpatched CVE applies
impact: version fingerprinting enables targeted exploit; downloadable binaries can be reverse-engineered for client-side auth flaws; gwtest.jsp 500 may indicate misconfiguration; severity LOW-MEDIUM
testability: PASSIVE
[NEXT] HUMAN: The critical unlock for all OAuth hypotheses is obtaining a valid cidaas client_id. Options: (1) extract from HORNBACH mobile app (de.hornbach on Google Play) via APK decompile — look for `ClientId` in cidaas SDK config (strings.xml or Cidaas initialization); (2) intercept OAuth redirect in browser during manual login at www.hornbach.de to capture client_id from authz redirect; (3) check Apple App Store listing for OAuth redirect URI scheme. Until client_id is obtained, unauthenticated introspection testing and Citrix NetScaler version audit are the most productive passive activities.
[RISK] hornbach: 43/100 — cidaas tenant is primary live auth surface; unauthenticated introspection endpoint confirmed abnormal (RFC 7662 violation) but impact gated on client_id; SAP API Gateway on api.hornbach.de identified but minimal route surface; Citrix NetScaler AAA on auth.hornbach.de is employee-facing VPN with full version disclosure; dev/preprod subdomains exist but are IP-restricted/GCP-gated; www.hornbach.de bot-walled (FingerprintJS); Mirakl marketplace is separate auth-gated surface; scope broad but CDN-heavy and gates hard.
## 2026-09-04 14:12:30 UTC [target] (model bigpickle)
[NEW] auth.hornbach.com/token-srv/revoke: POST returns HTTP 200 "OK" without client auth — RFC 7009 violation; second unauthenticated token management endpoint alongside introspection
[NEW] auth.hornbach.com/login-srv/social/token: GET returns HTTP 500 with empty error JSON + `Access-Control-Allow-Origin: *`
[CHANGED] auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053 "par is not enabled for this tenant")
[CHANGED] api.hornbach.de: POST root returns 404 JSON with X-CorrelationID — consistent SAP APIM, no new routes
[PRIO] auth.hornbach.com, 8.6, attack_surface:9, business_value:9, tech_exposure:9, gate_ease:7, cloud_surface:8, freshness:9
[PRIO] auth.hornbach.de, 6.4, attack_surface:6, business_value:7, tech_exposure:8, gate_ease:5, cloud_surface:4, freshness:8
[PRIO] hornbach-mp.mirakl.net, 5.5, attack_surface:6, business_value:6, tech_exposure:6, gate_ease:3, cloud_surface:5, freshness:7
[HYP] Unauthenticated token revocation enables silent session killing
class: AUTH
asset: auth.hornbach.com/token-srv/revoke
confidence: 55
reasoning: POST to /token-srv/revoke accepts any token value without client authentication (HTTP 200 "OK"). RFC 7009 §2.1 requires client auth; cidaas metadata confirms auth_methods_required but live endpoint ignores them entirely. Parallel to unauthenticated introspection — systemic cidaas token management auth bypass for this tenant.
evidence_needed: valid access_token to demonstrate revocation of an active session
verify_steps: (DONE) POST fake token → 200 "OK" without auth; NEXT: obtain real token, revoke unauthenticated, confirm session killed
impact: silent session revocation → individual account DoS; combined with token theft: steal → revoke → user forced re-auth → attacker intercepts; severity MEDIUM
testability: AUTH_HELPED
[HYP] Unauthenticated token introspection leaks token metadata
class: AUTH
asset: auth.hornbach.com/token-srv/introspect
confidence: 55
reasoning: POST to /token-srv/introspect returns HTTP 200 {"active":false} without any client auth. Confirmed alongside unauthenticated revocation — both endpoints share the same auth bypass pattern, indicating systemic misconfiguration in cidaas token management for this tenant. Previously at confidence 50; strengthened by parallel revoke finding.
evidence_needed: valid access_token to prove metadata exfiltration (sub, scope, exp, client_id)
verify_steps: (DONE) unauthenticated POST returns 200; NEXT: introspect real token to confirm metadata leak
impact: token metadata disclosure (active sessions, user identity, scopes, expiry); severity MEDIUM
testability: AUTH_HELPED
[HYP] Social token endpoint server error disclosure
class: OTHER
asset: auth.hornbach.com/login-srv/social/token
confidence: 40
reasoning: GET to /login-srv/social/token returns HTTP 500 with `{"success":false,"status":500,"error":{}}` + `Access-Control-Allow-Origin: *`. The empty error object suggests unhandled exception. CORS header on error response is unusual.
evidence_needed: POST with various provider/token params to trigger different error paths
verify_steps: POST with Content-Type: application/json and {"provider":"google","token":"fake"}
impact: potential information disclosure via error messages; severity LOW
testability: PASSIVE
[PARKED] Unauthenticated OAuth client registration: REJECTED — 404 on ALL methods; registration disabled at routing
[PARKED] OAuth redirect_uri validation bypass: confidence 50 but blocked on client_id; ~15+ patterns attempted, all AUTH10007; www.hornbach.de bot-walled blocks frontend
[PARKED] cidaas JWT alg confusion: confidence 40 < 45 — blocked on client_id + token; mature provider likely pinned
[PARKED] Device code flow abuse: confidence 45 — requires valid client_id; social engineering makes it unreliable
[FINAL] 1. Unauthenticated token revocation (confidence 55, AUTH_HELPED, MEDIUM)
[FINAL] 2. Unauthenticated token introspection (confidence 55, AUTH_HELPED, MEDIUM)
[FINAL] 3. Social token endpoint 500 (confidence 40, PASSIVE, LOW)
[NEXT] HUMAN: The critical unlock is obtaining a valid cidaas client_id. cidaas Android SDK stores it as `<item name="ClientId" type="string">` in cidaas.xml or strings.xml. Options: (1) download HORNBACH APK from APK mirror and extract ClientId via strings/grep; (2) use mitmproxy/Charles during manual hornbach.de login to capture authz redirect with client_id; (3) check GitHub repos for hardcoded HORNBACH cidaas client_ids. Until obtained, the unauthenticated revocation+introspection pair is the strongest confirmed finding.
[LEARN] ACCEPTED class AUTH @ auth.hornbach.com/token-srv/revoke: token revocation endpoint accessible unauthenticated, RFC 7009 violation — second token management endpoint missing client auth
[LEARN] ACCEPTED class AUTH @ auth.hornbach.com/token-srv/introspect: unauthenticated introspection confirmed systemic; strengthened by parallel revoke finding
[LEARN] REJECTED class OTHER @ auth.hornbach.com/authz-srv/par: PAR explicitly disabled (AUTH10053)
[LEARN] ACCEPTED class OTHER @ auth.hornbach.com/login-srv/social/token: social token resolver returns HTTP 500 on GET + CORS wildcard
[RISK] hornbach: 44/100 — cidaas tenant has TWO unauthenticated token management endpoints (introspection + revocation) forming confirmed RFC 7662/709 violation pattern; dynamic client registration disabled; PAR disabled; ~15+ client_id patterns failed (UUID-format); www.hornbach.de bot-walled; Citrix NetScaler AAA with full version exposure; SAP APIM with internal hostname leak; scope broad but CDN-heavy and gate-hard; critical blocker: client_id acquisition for all OAuth testing.
