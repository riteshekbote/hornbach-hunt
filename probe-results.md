
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
