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
