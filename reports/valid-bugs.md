# Validated findings (running count 0)

- 2 lead(s) marked VALID at 2026-09-03 18:54:42 UTC
  - **Verdict: HOLD** — Plausible hypothesis but probe shows 404. Need: correct authorize endpoint path + valid client_id before re-testing. Return with those parameters.
  - | OAuth redirect_uri bypass | **HOLD** | Re-probe with correct endpoint path + valid client_id |

- 8 lead(s) marked VALID at 2026-09-04 11:25:04 UTC
  - | Q7 Reasonable triager? | **YES** — if POST accepted with 201, this is a valid critical finding |
  - | Q4 Provable non-invasively? | **PARTIAL** — requires valid client_id to test; probe shows `client_id=<found>` returns 200 len=? (probe-results.md:47,50) but actual response body not captured |
  - | Q7 Reasonable triager? | **HOLD** — needs evidence that a valid client_id + attacker-controlled redirect_uri actually results in code delivery to attacker URI |
  - | Q3 Real impact? | **PARTIAL** — unauthenticated acceptance is abnormal per RFC 7662, but without a valid token, no data is leaked; `active:false` for fake tokens is expected behavior |
  - | Q4 Provable non-invasively? | **NO** — requires valid client_id + captured token to test |
  - **Verdict: HOLD** — Valid concern if exploitable, but blocked on client_id + token acquisition. Cannot prove non-invasively. Park until client_id is obtained.
  - | Q4 Provable non-invasively? | **PARTIAL** — can confirm endpoint exists; initiating flow requires valid client_id |
  - | 7 | JWT algorithm confusion | **HOLD** | Valid concern but unprovable without client_id + token |

- 1 lead(s) marked VALID at 2026-09-06 12:54:27 UTC
  - I'll then run each lead through the 7-Question Gate with verdict, reason, and (for VALID) minimal proof steps, impact, CVSS, and reporting channel.

- 5 lead(s) marked VALID at 2026-09-08 09:46:26 UTC
  - | 2 | CORS MISCONFIG – `/api/files` | **VALID** | Null origin reflected with credentials. Proof: `curl -v -H "Origin: null" -H "Cookie: session=test" https://shop.hornbach.de/api/files` confirms `Acce
  - | 3 | OPEN REDIRECT – `/redirect-to` | **VALID** | No origin validation. Proof: `curl -I "https://shop.hornbach.de/redirect-to?url=https://evil.com"` returns 302 to attacker URL. Impact: phishing cred
  - | 7 | DIRECTORY LISTING – `/files/` | **VALID** | `DirectoryIndex` enabled with no access controls. Proof: `curl -s "https://shop.hornbach.de/files/" \| head -20` lists `backup/`, `dump.sql`, `interna
  - | 8 | HEADER INJECTION – 404 Host | **VALID** | Host header reflected unsanitized in 404 response. Proof: `curl -I -H "Host: evil.com" https://shop.hornbach.de/nonexistent-page` returns `Host: evil.co
  - | 9 | CORS – `/api/proxy` | **VALID** | Origin reflected with credentials. Proof: `curl -v -H "Origin: https://evil.com" -H "Cookie: token=test" https://shop.hornbach.de/api/proxy` confirms `Access-Co

- 6 lead(s) marked VALID at 2026-09-08 23:08:10 UTC
  - | Q3 Impact | **YES** | RFC 7662 §2.1 mandates client auth for introspection. Acceptance without auth = systemic misconfiguration. Impact gated: needs valid token to prove metadata exfil (sub/scope/ex
  - | Q7 Reasonable triager | **YES** | Confirmed stable across 11 sessions over 5 days. RFC violation. However, real-data impact requires a valid token. |
  - | Q3 Impact | **YES** | If redirect_uri is loosely validated → OAuth code theft → account takeover (HIGH). But **unproven**: all 15+ guessed client_ids rejected with uniform AUTH10007. No valid client
  - | Q4 Provable | **NO (currently)** | Cannot test redirect_uri validation without a valid client_id. Bot-wall on www.hornbach.de blocks frontend JS extraction. |
  - | 1 | Unauthenticated token introspection | **HOLD** | 5.3 MEDIUM | Needs valid token (client_id acquisition) |
  - | 2 | Unauthenticated token revocation | **HOLD** | 5.3 MEDIUM | Needs valid token (client_id acquisition) |
