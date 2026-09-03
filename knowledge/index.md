# Knowledge Base (seed)
- 2026-09-03 REJECTED class WILDCARD_DOM: wildcard DNS dominates hornbach.com zone; no dedicated hosts recovered; move to CDN-proxied surface analysis instead of subdomain enumeration
- 2026-09-03 ACCEPTED class OATH: third-party IdP (cidaas) integration on auth.hornbach.com creates OAuth/OIDC attack surface worth investigating
- 2026-09-03 REJECTED MISCONFIG @ login.hornbach.com: Fastly shared SNI CNAME takeover unlikely without Fastly account access; active service confirmed via Varnish header and resolving IP.
- 2026-09-03 REJECTED class MISCONFIG @ login.hornbach.com: Fastly CNAME takeover confirmed unlikely — active service (Varnish header, 200 response, resolving IP) eliminates takeover vector.
- 2026-09-03 ACCEPTED class AUTH @ auth.hornbach.com: cidaas OAuth surface confirmed live; client_id enumeration is prerequisite for redirect_uri/state flaw testing.
- 2026-09-03 REJECTED class WILDCARD_DOM: reconfirmed — wildcard DNS dominates zone; no new subdomains via passive enumeration.
- 2026-09-03 ACCEPTED class AUTH: cidaas CIAM platform on auth.hornbach.com exposes full OIDC provider metadata including registration_endpoint, device_authorization_endpoint, introspection_endpoint, and SCIM endpoint — broader attack surface than initially assessed
- 2026-09-03 ACCEPTED class OATH: Authorization endpoint confirmed live at authz-srv/authz with verbose error messages; redirect_uri validation testing requires valid client_id discovery first
