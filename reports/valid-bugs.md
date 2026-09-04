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
