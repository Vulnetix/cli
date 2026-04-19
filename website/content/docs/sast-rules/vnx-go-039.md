---
title: "VNX-GO-039 – Missing rate limiting on login endpoint"
description: "Detect Go HTTP handler functions named after login or sign-in operations that do not apply rate limiting, throttling, or lockout mechanisms, leaving authentication endpoints open to brute-force and credential-stuffing attacks."
---

## Overview

This rule flags Go HTTP handler functions whose names contain `Login`, `login`, `SignIn`, or `signin` but whose implementation does not reference any rate limiting, throttling, or lockout pattern — specifically the absence of identifiers such as `rate`, `throttle`, `limiter`, `RateLimit`, `rateLimit`, or `Throttle` within the handler. Authentication endpoints without rate limiting are directly exploitable by automated credential-stuffing and brute-force tools that can attempt thousands of password guesses per second. This maps to [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html).

Credential stuffing — the automated testing of username/password pairs from data breaches — is one of the most common attack techniques against web applications, responsible for billions of fraudulent login attempts daily.

**Severity:** Medium | **CWE:** [CWE-307 – Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html) | **OWASP:** [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

## Why This Matters

Without rate limiting, an attacker can attempt authentication with unlimited speed, constrained only by network bandwidth and the server's processing capacity. Modern credential-stuffing tools such as Sentry MBA, OpenBullet, and similar frameworks operate against millions of accounts simultaneously using distributed bot networks that rotate IP addresses, defeat simple IP-based rate limits, and appear as legitimate traffic. Even a modest password list of one million common passwords becomes a viable brute-force attack against a single account if there is no lockout.

The consequences range from account takeover and financial fraud to regulatory exposure under GDPR, PCI-DSS, and SOC 2, all of which include requirements around authentication security. MITRE ATT&CK T1110 (Brute Force) specifically covers credential stuffing, password spraying, and password cracking — all of which are directly enabled by the absence of authentication rate limiting. CAPEC-49 (Password Brute Forcing) describes the full attack pattern in detail. Well-implemented rate limiting reduces the practical value of credential stuffing to near zero.

## What Gets Flagged

The rule fires on handler functions that appear to implement login or sign-in logic without referencing any rate limiting mechanism.

```go
// FLAGGED: login handler with no rate limiting
func loginHandler(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")

    user, err := db.FindByUsername(username)
    if err != nil || !checkPassword(user.PasswordHash, password) {
        http.Error(w, "invalid credentials", http.StatusUnauthorized)
        return
    }
    issueSessionToken(w, user)
}

// FLAGGED: sign-in route handler, no throttle applied
func signInHandler(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Email    string `json:"email"`
        Password string `json:"password"`
    }
    json.NewDecoder(r.Body).Decode(&creds)
    authenticate(w, creds.Email, creds.Password)
}
```

```go
// SAFE: login handler wrapped with rate limiter middleware
import "golang.org/x/time/rate"

var loginLimiter = rate.NewLimiter(rate.Every(time.Second), 5) // 5 req/s burst

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if !loginLimiter.Allow() {
        http.Error(w, "too many requests", http.StatusTooManyRequests)
        return
    }
    username := r.FormValue("username")
    password := r.FormValue("password")
    // ... authentication logic ...
}
```

## Remediation

1. **Apply per-IP rate limiting using `golang.org/x/time/rate`** or a token-bucket middleware library. Store per-IP limiters in a `sync.Map` with periodic cleanup to prevent memory exhaustion.

   ```go
   import (
       "sync"
       "time"

       "golang.org/x/time/rate"
   )

   var (
       loginLimiters sync.Map
   )

   func getLoginLimiter(ip string) *rate.Limiter {
       limiter, _ := loginLimiters.LoadOrStore(ip,
           rate.NewLimiter(rate.Every(10*time.Second), 3)) // 3 attempts per 10s
       return limiter.(*rate.Limiter)
   }

   // SAFE: rate-limited login handler
   func loginHandler(w http.ResponseWriter, r *http.Request) {
       ip := r.RemoteAddr
       limiter := getLoginLimiter(ip)
       if !limiter.Allow() {
           w.Header().Set("Retry-After", "10")
           http.Error(w, "too many login attempts", http.StatusTooManyRequests)
           return
       }
       // ... authentication logic ...
   }
   ```

2. **Implement account lockout** in addition to IP-based rate limiting. After a configurable number of failed attempts (e.g. 10), lock the account and require email verification to unlock. Store failed attempt counts in Redis or your database, keyed by account identifier.

3. **Use a middleware-level rate limiter** (e.g. `github.com/ulule/limiter`) that enforces limits transparently across all authentication routes, integrates with Redis for distributed deployments, and supports multiple rate limit strategies (sliding window, fixed window, token bucket).

## References

- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [CAPEC-49: Password Brute Forcing](https://capec.mitre.org/data/definitions/49.html)
- [MITRE ATT&CK T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/)
- [golang.org/x/time/rate package documentation](https://pkg.go.dev/golang.org/x/time/rate)
