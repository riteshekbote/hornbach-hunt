
## 2026-09-02 21:46:11 UTC


## 2026-09-02 23:55:43 UTC


## 2026-09-03 03:44:54 UTC


## 2026-09-03 08:47:26 UTC


## 2026-09-03 13:26:06 UTC


## 2026-09-03 17:21:40 UTC
https://auth.hornbach.com/oauth2/authorize?response_type=code&client_id=<public_client_id>&redirect_uri=https://evil.com&scope=openid -> HTTP 404
https://auth.hornbach.com.attacker.com -> ERR <urlopen error [SSL: TLSV1_ALERT_INTERNAL_ERROR] t
https://hornbach.com/@evil.com -> 200 len=3038
https://login.hornbach.com/ -> 200 len=3038
https://auth.hornbach.com/oauth2/authorize?response_type=code&client_id=public&redirect_uri=https://example.com&scope=openid -> HTTP 404
https://auth.hornbach.com/ -> 200 len=3038

## 2026-09-03 20:03:29 UTC
https://auth.hornbach.com/ -> 200 len=3038
https://auth.hornbach.com/oauth2/authorize?response_type=code&client_id=<candidate>&redirect_uri=https://hornbach.de/callback&scope=openid -> HTTP 404
https://login.hornbach.com/ -> 200 len=3038
https://hornbach.com/@evil.com` -> 200 len=3038
https://hornbach.com/@evil.com -> 200 len=3038
https://auth.hornbach.com/apps-srv/clients/register` -> HTTP 404
https://auth.hornbach.com/apps-srv/clients/register -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?
https://auth.hornbach.com/authz-srv/device/authz -> HTTP 400

## 2026-09-03 22:32:00 UTC
https://auth.hornbach.com/apps-srv/clients/register` -> HTTP 404
https://auth.hornbach.com/apps-srv/clients/register -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?
https://auth.hornbach.com/ -> 200 len=3038
https://auth.hornbach.com/oauth2/authorize?response_type=code&client_id=<candidate>&redirect_uri=https://hornbach.de/callback&scope=openid -> HTTP 404

## 2026-09-04 00:43:50 UTC


## 2026-09-04 05:17:58 UTC
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?

## 2026-09-04 09:58:05 UTC
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?
https://auth.hornbach.com/token-srv/introspect -> HTTP 404

## 2026-09-04 14:20:26 UTC
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?

## 2026-09-04 17:49:15 UTC
https://auth.hornbach.com/token-srv/revoke -> HTTP 404

## 2026-09-04 20:01:33 UTC
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?
https://auth.hornbach.com/token-srv/revoke -> HTTP 404

## 2026-09-04 22:16:16 UTC
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz -> 200 len=?

## 2026-09-05 00:15:34 UTC
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?

## 2026-09-05 04:42:34 UTC
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?

## 2026-09-05 08:45:32 UTC
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?
https://auth.hornbach.com/authz-srv/authz -> 200 len=?

## 2026-09-05 12:18:44 UTC
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?

## 2026-09-05 15:26:23 UTC
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?

## 2026-09-05 17:43:17 UTC
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?

## 2026-09-05 19:34:12 UTC
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?
https://auth.hornbach.com/authz-srv/authz -> 200 len=?

## 2026-09-05 21:49:00 UTC
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<found>&redirect_uri=https://evil.com&scope=openid -> 200 len=?

## 2026-09-05 23:41:27 UTC
https://auth.hornbach.com/token-srv/introspect -> HTTP 404
https://auth.hornbach.com/token-srv/revoke -> HTTP 404
https://auth.hornbach.com/authz-srv/authz?response_type=code&client_id=<valid_client_id>&redirect_uri=https://evil.com&scope=openid -> 200 len=?
