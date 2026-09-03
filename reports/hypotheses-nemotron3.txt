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
