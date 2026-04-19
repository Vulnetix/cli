---
title: "VNX-GO-031 – Missing signature validation on JWT"
description: "Detects JWT parsing that does not verify the token's cryptographic signature, allowing attackers to forge arbitrary claims."
---

## Overview

This rule flags Go code that calls `jwt.Parse` or `jwt.Decode` without providing a key function that validates the signing method and returns the appropriate verification key. Without signature validation, an attacker can craft a JWT with any claims they choose — including elevated roles or different user identities — and the application will accept it as authentic. This maps to [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html).

The most well-known exploit of this class is the `alg: none` attack, where an attacker strips the signature and sets the algorithm field to `"none"`. Libraries that accept whatever algorithm the token header specifies will then skip signature verification entirely. Even libraries that reject `alg: none` by default may be misused when the key function is omitted or returns without error unconditionally.

**Severity:** High | **CWE:** [CWE-347 – Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html) | **OWASP:** [A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)

## Why This Matters

JWTs are widely used to carry authentication and authorization state between services. If an application parses a JWT and reads its claims without verifying the signature, the entire trust model of the token collapses. Any user who can observe a legitimate token can modify the `sub`, `role`, or `exp` fields, re-encode the header and payload in base64url, append no signature, and present the result as a valid token. The application will grant the forged claims without any server-side state check.

This attack requires no special capability — only the ability to decode a JWT (which is trivially done with any base64 decoder) and construct a new one. Real-world incidents include privilege escalation in multi-tenant SaaS platforms where the `alg: none` technique was used to forge admin tokens. CAPEC-64 (Using Slashdot Effect) and related JWT-specific attack patterns are well-documented in penetration testing toolkits.

## What Gets Flagged

The rule flags `jwt.Parse` or `jwt.Decode` calls without a key function that checks the signing method:

```go
// FLAGGED: Parse with no key function — signature never verified
import "github.com/golang-jwt/jwt/v5"

func getUser(tokenString string) (*Claims, error) {
    token, err := jwt.Parse(tokenString, nil)
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        return extractClaims(claims), nil
    }
    return nil, err
}

// FLAGGED: key function does not check signing method
func parseToken(tokenStr string) (*jwt.Token, error) {
    return jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
        return []byte("secret"), nil // algorithm not verified
    })
}
```

## Remediation

1. **Always use `jwt.ParseWithClaims`** with a key function that explicitly checks the signing method before returning the key:
   ```go
   // SAFE: signing method validated before key is returned
   import (
       "errors"
       "github.com/golang-jwt/jwt/v5"
   )

   type AppClaims struct {
       UserID string `json:"user_id"`
       Role   string `json:"role"`
       jwt.RegisteredClaims
   }

   var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

   func parseToken(tokenStr string) (*AppClaims, error) {
       token, err := jwt.ParseWithClaims(tokenStr, &AppClaims{},
           func(token *jwt.Token) (interface{}, error) {
               if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                   return nil, errors.New("unexpected signing method")
               }
               return jwtSecret, nil
           })
       if err != nil {
           return nil, err
       }
       claims, ok := token.Claims.(*AppClaims)
       if !ok || !token.Valid {
           return nil, errors.New("invalid token")
       }
       return claims, nil
   }
   ```

2. **For RSA/ECDSA tokens**, verify the algorithm family and use the public key:
   ```go
   // SAFE: RSA signature validation
   func parseRSAToken(tokenStr string, pubKey *rsa.PublicKey) (*AppClaims, error) {
       return jwt.ParseWithClaims(tokenStr, &AppClaims{},
           func(token *jwt.Token) (interface{}, error) {
               if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
                   return nil, errors.New("unexpected signing method")
               }
               return pubKey, nil
           })
   }
   ```

3. **Never accept the algorithm from the token header as authoritative.** Your key function should enforce a specific algorithm (or family) regardless of what the token claims.

## References

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [OWASP JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP Top 10 A02:2021 – Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [golang-jwt/jwt v5 documentation](https://pkg.go.dev/github.com/golang-jwt/jwt/v5)
- [RFC 7519 – JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [Auth0 – Critical Vulnerabilities in JSON Web Token Libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [CAPEC-64: Using Slashdot Effect](https://capec.mitre.org/data/definitions/64.html)
