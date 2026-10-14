---
title: "VNX-GO-032 – JWT missing expiration validation"
description: "Detects JWT expiry that is never enforced in Go: claims validation turned off (WithoutClaimsValidation, SkipClaimsValidation, jwx WithValidate(false)), go-jose Claims with no Validate call, and tokens issued from a claims literal with no exp/ExpiresAt/Expiry."
---

## Overview

This rule flags Go code that never enforces a JWT's expiry: claims validation switched off by a parser option, go-jose claims that are never passed to `Validate`, or a token issued from a claims literal with no `exp`. When expiration is not validated, stolen or compromised tokens remain valid indefinitely, eliminating the time-bounded security guarantee that JWTs are designed to provide. This maps to [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html).

Session expiration is one of the fundamental controls in authentication system design. Short-lived tokens limit the window of opportunity for an attacker who has obtained a token through XSS, network interception, or a compromised log file. Skipping expiration validation removes this protection entirely, turning a JWT into a permanent credential that cannot be revoked without additional infrastructure.

**Severity:** Medium | **CWE:** [CWE-613 – Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) | **OWASP:** [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

## Why This Matters

In practice, tokens get leaked through browser history, log files, referrer headers, and client-side vulnerabilities. A short expiration window — typically 15 minutes to 1 hour for access tokens — significantly reduces the damage caused by any single token leak. Without expiration enforcement, a leaked token obtained through any channel remains valid until the signing secret is rotated or a deny-list entry is added, both of which require additional infrastructure and manual intervention.

This is especially significant in microservice architectures where JWTs are passed between services as bearer tokens. A compromised internal service can replay old tokens to peer services indefinitely if none of them enforce expiration. The combination of missing expiration validation with missing signature validation (VNX-GO-031) effectively makes JWTs equivalent to opaque strings with no security properties.

## What Gets Flagged

Verification that skips the expiry check, and tokens issued with no expiry at all.

```go
// FLAGGED: claims validation (exp, nbf, iat) switched off
var parser = jwt.NewParser(jwt.WithoutClaimsValidation())
p := &jwt.Parser{SkipClaimsValidation: true}
jwt.Parse(raw, jwt.WithKey(jwa.RS256, pub), jwt.WithValidate(false))

// FLAGGED: go-jose checks only the signature in Claims; nothing calls Validate
if err := tok.Claims(providerKey, out); err != nil {

// FLAGGED: issued without exp, so it never expires
return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
    "sub": userID,
    "iat": time.Now().Unix(),
}).SignedString(secret)
```

Not flagged: claims built by a helper or passed in as a parameter (the expiry may be set there), default golang-jwt parsing (v4+ checks `exp` when present), `WithExpirationRequired`, `WithValidate(true)`, go-jose claims followed by `ValidateWithLeeway`, and test files. golang-jwt accepts a token with no `exp` unless `jwt.WithExpirationRequired()` is set; that default is not reported.

## Remediation

1. **Embed `jwt.RegisteredClaims`** in your claims struct and always check `token.Valid`, which includes expiration verification in golang-jwt/jwt v5:
   ```go
   // SAFE: RegisteredClaims embeds ExpiresAt; token.Valid enforces it
   import (
       "errors"
       "time"
       "github.com/golang-jwt/jwt/v5"
   )

   type AppClaims struct {
       UserID string `json:"user_id"`
       Role   string `json:"role"`
       jwt.RegisteredClaims
   }

   func parseToken(tokenStr string) (*AppClaims, error) {
       token, err := jwt.ParseWithClaims(tokenStr, &AppClaims{}, keyFunc)
       if err != nil {
           return nil, err
       }
       claims, ok := token.Claims.(*AppClaims)
       if !ok || !token.Valid {
           return nil, errors.New("invalid or expired token")
       }
       return claims, nil
   }
   ```

2. **Set a short expiration when issuing tokens** to limit the blast radius of any compromise:
   ```go
   // SAFE: token issued with 15-minute expiry
   func issueToken(userID string) (string, error) {
       claims := AppClaims{
           UserID: userID,
           RegisteredClaims: jwt.RegisteredClaims{
               ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
               IssuedAt:  jwt.NewNumericDate(time.Now()),
               Issuer:    "my-service",
           },
       }
       token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
       return token.SignedString(jwtSecret)
   }
   ```

3. **Do not use `jwt.WithoutClaimsValidation()`** or similar options that skip the standard claims validation. If you need clock skew tolerance, use `jwt.WithLeeway` with a small value (e.g., 30 seconds) rather than disabling validation entirely.

## References

- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Top 10 A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [golang-jwt/jwt v5 – Registered Claims](https://pkg.go.dev/github.com/golang-jwt/jwt/v5#RegisteredClaims)
- [RFC 7519 Section 4.1.4 – "exp" (Expiration Time) Claim](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4)
- [CAPEC-64: Using Slashdot Effect](https://capec.mitre.org/data/definitions/64.html)
