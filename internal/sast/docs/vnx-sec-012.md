---
title: "VNX-SEC-012 – CORS Wildcard or Origin Reflection"
description: "Detects a server that answers cross-origin requests from any website: Access-Control-Allow-Origin echoing the request Origin without an allowlist check, set to *, or CORS middleware configured for every origin."
---

## Overview

This rule reports three shapes: the `Access-Control-Allow-Origin` header set to the request's own `Origin` header (directly or through a variable read from it a few lines above) with no allowlist check on the origin; the header set to `*` (`w.Header().Set`, `response[...] =`, PHP `header()`, nginx `add_header`, Apache `Header set`, the ingress-nginx `cors-allow-origin` annotation); and CORS middleware configured for every origin (AWS CDK `allowOrigins: Cors.ALL_ORIGINS`, FastAPI `allow_origins=["*"]`, Flask-CORS `CORS(app)`, django-cors-headers `CORS_ALLOW_ALL_ORIGINS = True`, gin `AllowAllOrigins`, rs/cors `AllowOriginFunc` returning true, Spring `allowedOriginPatterns("*")` and bare `@CrossOrigin`, ASP.NET Core `AllowAnyOrigin()` and `SetIsOriginAllowed(_ => true)`, Laravel and rack-cors wildcards). It does not report a wildcard whose configuration explicitly disables credentials nearby, specific origins, an origin checked against an allowlist, the header sent by client code (`fetch`/`axios` request headers), assertions, tests and documentation. CORS in JavaScript and TypeScript servers (`res.setHeader`, the `cors` package, Fastify and NestJS) is reported by VNX-942, so one problem is not reported twice; for those files this rule reports only the AWS CDK construct. CORS controls which websites can read responses from your API using cross-origin JavaScript. Setting it too broadly means any malicious website can make authenticated requests to your API on behalf of a logged-in user and read the responses.

**Severity:** High | **CWE:** [CWE-942 – Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)

## Why This Matters

There is an important distinction between two types of permissive CORS:

**Wildcard (`*`)**: This allows any origin to make cross-origin requests, but browsers will not send cookies or `Authorization` headers with wildcards. This is appropriate for truly public APIs (like a CDN or public data endpoint) but dangerous for any API that uses cookies or tokens for authentication.

**Origin reflection (`origin: true` in Express, or echoing `Origin` back as `Access-Control-Allow-Origin`)**: This is the more dangerous pattern. It appears to be dynamic, but effectively allows any origin — and crucially, it can be combined with `Access-Control-Allow-Credentials: true`. With credentials enabled and an overly permissive origin, any website can make credentialed cross-origin requests to your API, read the responses, and exfiltrate data on behalf of your logged-in users.

The CORS misconfiguration in the 2018 British Airways breach (MITRE ATT&CK T1189) exemplifies how attackers exploit this to steal session tokens and payment data.

## What Gets Flagged

```python
# FLAGGED: FastAPI wildcard CORS
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,  # dangerous combined with wildcard
    allow_methods=["*"],
)
```

```typescript
// FLAGGED: AWS CDK API Gateway preflight for every origin
defaultCorsPreflightOptions: {
  allowOrigins: apigw.Cors.ALL_ORIGINS,
  allowCredentials: true,
},
```

Express, Fastify and NestJS servers (`res.setHeader('Access-Control-Allow-Origin', req.headers.origin)`, `app.use(cors())`, `cors({ origin: true })`) are reported by [VNX-942](../vnx-942/).

```go
// FLAGGED
w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
r.Use(cors.New(cors.Config{AllowAllOrigins: true, AllowCredentials: true}))
```

```nginx
# FLAGGED
add_header Access-Control-Allow-Origin $http_origin always;
```

Not flagged: `if (ALLOWED.has(origin)) res.setHeader('Access-Control-Allow-Origin', origin)`, `allow_origins=["https://app.example.com"]`, and `allow_origins=["*"]` beside `allow_credentials=False`.

## Remediation

1. **Replace the wildcard or reflection with an explicit allowlist** of trusted origins:

```python
# SAFE: explicit allowlist of trusted origins (FastAPI)
from fastapi.middleware.cors import CORSMiddleware

ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)
```

```javascript
// SAFE: validate origin against allowlist in Express
const ALLOWED_ORIGINS = new Set([
    'https://app.example.com',
    'https://admin.example.com',
]);

app.use(cors({
    origin: (origin, callback) => {
        if (!origin || ALLOWED_ORIGINS.has(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
}));
```

2. **Never combine `Access-Control-Allow-Credentials: true` with a wildcard or reflected origin.** Browsers will block this combination in modern versions, but older browsers may not, and the coding pattern itself signals a CORS misconfiguration.

3. **For truly public APIs** (no authentication, no sensitive data), a wildcard without credentials is acceptable:

```python
# SAFE: public read-only API — wildcard without credentials is OK
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # explicitly no credentials
)
```

4. **Review preflight handling.** Ensure that `OPTIONS` preflight requests are handled correctly and that `Access-Control-Max-Age` is set to cache preflight results and reduce latency.

5. **Test your CORS policy** using browser devtools or tools like `curl -H "Origin: https://evil.com" -v` to verify that unauthorized origins receive an appropriate rejection.

## References

- [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
- [OWASP: CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html)
- [MDN: CORS](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger: CORS vulnerabilities](https://portswigger.net/web-security/cors)
- [MITRE ATT&CK T1189 – Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
- [CAPEC-111: JSON Hijacking](https://capec.mitre.org/data/definitions/111.html)
