## 2026-09-03 17:21:18 UTC [target] (model nemotron3)
[PRIO] auth.hornbach.com,7.55,attack_surface=8,business_value=9,tech_exposure=7,gate_ease=10,cloud_surface=6,freshness=5
[PRIO] login.hornbach.com,6.55,attack_surface=6,business_value=8,tech_exposure=5,gate_ease=10,cloud_surface=5,freshness=5
[PRIO] hornbach.com,5.35,attack_surface=4,business_value=7,tech_exposure=3,gate_ease=10,cloud_surface=4,freshness=5
[HYP] cidaas OAuth redirect_uri validation bypass
class: AUTH
asset: auth.hornbach.com (→ hornbach-prod.cidaas.eu)
confidence: 65
reasoning: auth.hornbach.com CNAMEs to hornbach-prod.cidaas.eu (cidaas CIAM). cidaas implements OAuth/OIDC. Common misconfiguration: loose redirect_uri validation allowing subdomain/path traversal or wildcard matching. Redirect goes to hornbach.de (different TLD), increasing risk of cross-domain OAuth code theft.
evidence_needed: OAuth authorize endpoint accepts redirect_uri with path traversal (../), subdomain variation (auth.hornbach.com.evil.com), or wildcard (*.hornbach.com) and returns authorization code to attacker-controlled URI.
verify_steps: GET https://auth.hornbach.com/oauth2/authorize?response_type=code&client_id=<public_client_id>&redirect_uri=https://evil.com&scope=openid — observe if redirect_uri accepted (302 to evil.com with code) or rejected (error). Test variations: https://hornbach.de.evil.com, https://auth.hornbach.com.attacker.com, https://hornbach.com/@evil.com
impact: Attacker steals OAuth authorization code → exchanges for access/refresh tokens → full account takeover (AUTH class, HIGH severity)
testability: PASSIVE
[HYP] Fastly CNAME takeover on login.hornbach.com
class: MISCONFIG
asset: login.hornbach.com (→ n.sni.global.fastly.net)
confidence: 45
reasoning: login.hornbach.com CNAMEs to n.sni.global.fastly.net (Fastly shared SNI). If Fastly service was deprovisioned but DNS remains, attacker could claim the Fastly service and serve content on login.hornbach.com. DNS resolves to 199.232.105.91 (Fastly IP). Inventory flags this as "Takeover-review flag".
evidence_needed: HTTP response from login.hornbach.com shows Fastly "Fastly error: unknown domain" or generic Fastly 404 page indicating unclaimed service, OR successful claim via Fastly API with same CNAME target.
verify_steps: GET https://login.hornbach.com/ — check response body for "Fastly error: unknown domain", "The request could not be satisfied", or generic Fastly 404. HEAD request to verify Server header remains Varnish/Fastly. Check if custom domain validation on Fastly allows claiming n.sni.global.fastly.net CNAME.
impact: Full control of login.hornbach.com subdomain → phishing, credential harvesting, session hijacking via cookie overflow (MISCONFIG class, CRITICAL if confirmed)
testability: PASSIVE
[HYP] Cross-domain session fixation via hornbach.de redirect chain
class: AUTH
asset: login.hornbach.com → www.hornbach.de/customer
confidence: 55
reasoning: login.hornbach.com (Fastly/Varnish) 302 redirects to www.hornbach.de/customer. Different TLD (.com → .de) with shared session cookies possible if cookie domain set to .hornbach.de or lax SameSite. Attacker could fixate session on .com, victim logs in on .de, attacker inherits session.
evidence_needed: Set-Cookie on login.hornbach.com or intermediate redirect has Domain=.hornbach.de (or .hornbach.com) with SameSite=None/Lax, allowing cross-TLD session sharing. Or session ID accepted across both domains without re-validation.
verify_steps: GET https://login.hornbach.com/ — capture Set-Cookie headers. Follow redirect chain to www.hornbach.de/customer — capture Set-Cookie headers. Check Domain attribute, SameSite, Secure flags. Test if session cookie from .com works on .de without re-auth.
impact: Session fixation → account takeover via cross-TLD cookie sharing (AUTH class, HIGH severity)
testability: PASSIVE
[PARKED] Fastly CNAME takeover on login.hornbach.com: confidence 45 < 50 threshold. Fastly shared SNI (n.sni.global.fastly.net) typically requires custom domain validation; takeover unlikely without Fastly account access. DNS resolves to active Fastly IP (199.232.105.91) — service likely claimed. Passive check only shows Varnish header, not Fastly error page.
[FINAL] 1. cidaas OAuth redirect_uri validation bypass (confidence 65, PASSIVE, HIGH)
[FINAL] 2. Cross-domain session fixation via hornbach.de redirect chain (confidence 55, PASSIVE, HIGH)
[NEXT] PROBE: GET https://auth.hornbach.com/oauth2/authorize?response_type=code&client_id=public&redirect_uri=https://example.com&scope=openid — observe redirect_uri validation behavior (accept/reject/error) and Location header. Use HEAD first to minimize impact.
[LEARN] REJECTED MISCONFIG @ login.hornbach.com: Fastly shared SNI CNAME takeover unlikely without Fastly account access; active service confirmed via Varnish header and resolving IP.
[RISK] hornbach: 70 — High-value auth surface (cidaas CIAM + cross-TLD redirect chain) with OAuth redirect_uri and session fixation attack vectors. No dedicated API surface discovered yet; wildcard-dominated zone limits subdomain enumeration. Priority on auth/logic flaws over infrastructure.
## 2026-09-03 20:03:02 UTC [target] (model nemotron3)
[NEW] auth.hornbach.com: OAuth authorize endpoint returns HTTP 404 (not 302) for test client_ids — suggests endpoint path may differ or requires valid registered client_id
[NEW] auth.hornbach.com: Root path (/) now returns HTTP 200 len=3038 (was 302 in inventory) — likely serves cidaas login UI directly
[NEW] login.hornbach.com: Root path (/) returns HTTP 200 len=3038 (was 302 in inventory) — serves content directly, not redirecting to hornbach.de
[CHANGED] Both auth.hornbach.com and login.hornbach.com return identical content length (3038) — possible shared error page or same backend response
[PRIO] auth.hornbach.com,7.30,attack_surface=8,business_value=9,tech_exposure=7,gate_ease=10,cloud_surface=6,freshness=4
[PRIO] login.hornbach.com,5.80,attack_surface=5,business_value=7,tech_exposure=4,gate_ease=10,cloud_surface=5,freshness=4
[PRIO] hornbach.com,5.10,attack_surface=4,business_value=7,tech_exposure=3,gate_ease=10,cloud_surface=4,freshness=4
[HYP] cidaas OAuth client_id enumeration via authorize endpoint
class: AUTH
asset: auth.hornbach.com/oauth2/authorize
confidence: 50
reasoning: Probe returned 404 for guessed client_ids ("public", "<public_client_id>"). cidaas uses numeric or UUID client_ids. Valid client_id would return login/consent page (200/302). Enumerating valid client_ids exposes OAuth clients for targeted redirect_uri/state attacks.
evidence_needed: Valid client_id returns HTTP 200 (login page) or 302 (redirect to consent) instead of 404. Brute-force or JS analysis of login page reveals registered client_ids.
verify_steps: GET https://auth.hornbach.com/ — parse HTML/JS for client_id references. GET https://auth.hornbach.com/oauth2/authorize?response_type=code&client_id=<candidate>&redirect_uri=https://hornbach.de/callback&scope=openid — test candidate client_ids from JS/config.
impact: Valid client_id enables OAuth flow testing for redirect_uri bypass, PKCE downgrade, state fixation (AUTH class, MEDIUM-HIGH)
testability: PASSIVE
[HYP] Cross-domain session fixation via shared error page cookies
class: AUTH
asset: login.hornbach.com / auth.hornbach.com (both return 200 len=3038)
confidence: 45
reasoning: Both subdomains return identical 3038-byte response (likely shared error/maintenance page). If Set-Cookie headers on this response have Domain=.hornbach.com or .hornbach.de with SameSite=Lax/None, attacker could fixate session via this page before victim authenticates on hornbach.de.
evidence_needed: Set-Cookie headers on 200 response from either host contain Domain attribute spanning .hornbach.com/.hornbach.de with permissive SameSite. Session ID from .com accepted on .de without re-auth.
verify_steps: GET https://login.hornbach.com/ -v — capture Set-Cookie headers. GET https://auth.hornbach.com/ -v — capture Set-Cookie headers. Check Domain, SameSite, Secure flags. Test cookie replay on www.hornbach.de.
impact: Session fixation → account takeover via cross-TLD cookie sharing (AUTH class, HIGH if confirmed)
testability: PASSIVE
[HYP] hornbach.com path traversal via @evil.com pattern returns 200
class: OTHER
asset: hornbach.com
confidence: 35
reasoning: Probe `https://hornbach.com/@evil.com` returned HTTP 200 len=3038. The @ syntax in path may indicate routing quirk (userinfo@host interpretation) or path normalization issue. Could allow open redirect or bypass path-based authz if backend parses @ as delimiter.
evidence_needed: Response differs from root path (diff content). Location header or meta redirect to attacker-controlled destination. Backend logs show @evil.com parsed as userinfo or separate parameter.
verify_steps: GET https://hornbach.com/@evil.com -v — compare response body/headers to root. Test variations: /@google.com, /@hornbach.de, /%40evil.com. Check for redirect headers or JS-based navigation.
impact: Potential open redirect or authz bypass if @ path reaches sensitive endpoints (OTHER class, LOW-MEDIUM)
testability: PASSIVE
[PARKED] Cross-domain session fixation via shared error page cookies: confidence 45 < 50 threshold; identical content length suggests generic error page unlikely to set auth cookies; no evidence of session cookies on unauthenticated error responses.
[PARKED] hornbach.com path traversal via @evil.com pattern: confidence 35 < 40 threshold; @ in path is valid URL userinfo syntax but browsers strip it before request; server seeing @evil.com in path suggests logging/routing artifact not exploitable redirect.
[FINAL] 1. cidaas OAuth client_id enumeration via authorize endpoint (confidence 50, PASSIVE, MEDIUM-HIGH)
[NEXT] PROBE: GET https://auth.hornbach.com/ -v — parse HTML/JS for cidaas client_id, OAuth config, or API endpoints; then test discovered client_id against /oauth2/authorize with redirect_uri=https://hornbach.de/callback
[LEARN] REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates takeover vector.
[LEARN] ACCEPTED class AUTH @ auth.hornbach.com: cidaas OAuth surface confirmed live; client_id enumeration is prerequisite for redirect_uri/state flaw testing.
[LEARN] REJECTED class WILDCARD_DOM: reconfirmed — wildcard DNS dominates zone; no new subdomains via passive enumeration.
[RISK] hornbach: 65 — Auth surface (cidaas) remains high-value but OAuth authorize endpoint requires valid client_id (404 on guesses). Cross-TLD session fixation less likely (identical error-page responses). No dedicated API surface discovered. Priority: enumerate cidaas client_id via login page JS, then test OAuth flows.
