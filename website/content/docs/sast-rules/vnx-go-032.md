---
title: "VNX-GO-032 – JWT missing expiration validation"
description: "Detects JWT parsing that does not verify the token's expiration claim, allowing expired or non-expiring tokens to be accepted indefinitely."
---

## Overview

This rule flags Go code that parses JWTs without checking the `exp` (expiration) claim — either by omitting `RegisteredClaims.ExpiresAt` from the claims struct, calling `jwt.Parse` or `jwt.Decode` and not validating `token.Valid`, or explicitly skipping expiration checks via parser options. When expiration is not validated, stolen or compromised tokens remain valid indefinitely, eliminating the time-bounded security guarantee that JWTs are designed to provide. This maps to [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html).

Session expiration is one of the fundamental controls in authentication system design. Short-lived tokens limit the window of opportunity for an attacker who has obtained a token through XSS, network interception, or a compromised log file. Skipping expiration validation removes this protection entirely, turning a JWT into a permanent credential that cannot be revoked without additional infrastructure.

**Severity:** Medium | **CWE:** [CWE-613 – Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html) | **OWASP:** [A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

## Why This Matters

In practice, tokens get leaked through browser history, log files, referrer headers, and client-side vulnerabilities. A short expiration window — typically 15 minutes to 1 hour for access tokens — significantly reduces the damage caused by any single token leak. Without expiration enforcement, a leaked token obtained through any channel remains valid until the signing secret is rotated or a deny-list entry is added, both of which require additional infrastructure and manual intervention.

This is especially significant in microservice architectures where JWTs are passed between services as bearer tokens. A compromised internal service can replay old tokens to peer services indefinitely if none of them enforce expiration. The combination of missing expiration validation with missing signature validation (VNX-GO-031) effectively makes JWTs equivalent to opaque strings with no security properties.

## What Gets Flagged

The rule flags JWT parsing that does not validate the expiration claim:

```go
// FLAGGED: token.Valid not checked, exp claim ignored
import "github.com/golang-jwt/jwt/v5"

func getClaimsUnsafe(tokenStr string) jwt.MapClaims {
    token, _ := jwt.Parse(tokenStr, keyFunc)
    claims, _ := token.Claims.(jwt.MapClaims)
    return claims // Valid never checked
}

// FLAGGED: custom claims struct without ExpiresAt, no expiry validation
type MyClaims struct {
    UserID string `json:"user_id"`
    // RegisteredClaims omitted — no exp field
}

func parseNoExpiry(tokenStr string) (*MyClaims, error) {
    token, err := jwt.ParseWithClaims(tokenStr, &MyClaims{}, keyFunc)
    claims, _ := token.Claims.(*MyClaims)
    return claims, err
}
```

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
