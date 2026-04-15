---
title: "VNX-JAVA-021 – Java Sensitive Data Logged"
description: "Detects logger calls that include variables or strings containing passwords, tokens, secrets, or API keys, which exposes credentials in log files and monitoring systems."
---

## Overview

Logging is a universal practice in Java applications, but log statements that inadvertently capture sensitive values — passwords, API tokens, secrets, or cryptographic keys — turn routine observability infrastructure into a credential-leakage channel. Once a sensitive value reaches a log sink, it propagates to every downstream system: log aggregators, SIEM platforms, cloud logging services, backup archives, and any developer workstation that tails the log. This is captured by CWE-532 (Insertion of Sensitive Information into Log File).

This rule flags calls to SLF4J, Log4j, java.util.logging, and similar logger facades — `log.debug()`, `log.info()`, `log.warn()`, `log.error()`, `log.trace()`, `log.fatal()` — on any line that also contains an identifier or string matching common credential naming patterns such as `password`, `passwd`, `secret`, `token`, `apikey`, `api_key`, `authkey`, `credential`, or `private_key` (case-insensitive).

The detection is intentionally broad: even if a developer passes a redacted value, the naming pattern on the same line as a logger call is sufficient to warrant review. False positives are preferable to missed credential leaks in logging code.

**Severity:** Medium | **CWE:** [CWE-532 – Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)

## Why This Matters

Log files are often treated as low-sensitivity output, but they are widely accessible — by all developers on a team, by CI/CD workers, by log aggregation services, and by cloud storage. A password or session token logged even once at DEBUG level during a troubleshooting session can persist in archived logs for years. If those logs are stored in a shared S3 bucket, shipped to a third-party SIEM, or inadvertently committed to a repository, the credential is effectively public.

In incident investigations, analysts routinely search log archives for keywords like `password` or `token` to reconstruct attacker activity. The same technique works for attackers who gain read access to a logging backend. The 2019 Capital One breach and numerous banking-sector incidents have involved credential exposure through logging.

A further risk is that many log backends are not encrypted at rest. Even in environments that encrypt storage, the logging pipeline itself — buffering, aggregation, forwarding — may transmit log entries in cleartext over internal networks. Keeping secrets out of logs eliminates this entire attack surface.

## What Gets Flagged

```java
// FLAGGED: password variable passed directly to logger
log.debug("Authenticating user {} with password {}", username, password);

// FLAGGED: token value interpolated into log message
log.info("Fetching resource with token: " + apiToken);

// FLAGGED: secret included in error log
log.error("OAuth failed, secret=" + clientSecret + ", error=" + e.getMessage());
```

## Remediation

1. **Never log sensitive values.** Omit passwords, tokens, and secrets from all log statements entirely. Log the fact that authentication occurred, not the credential used.

2. **Log only non-sensitive identifiers.** Reference a user ID, request ID, or masked representation instead of the raw credential.

3. **Mask before logging if unavoidable.** If a partial representation is genuinely needed for debugging, mask the value explicitly before it reaches the logger.

```java
// SAFE: log the event without the credential
log.debug("Authenticating user {}", username);

// SAFE: log a masked representation
String maskedToken = apiToken.substring(0, 4) + "****";
log.debug("Using token prefix: {}", maskedToken);

// SAFE: log success/failure without the credential
log.info("OAuth token refresh {} for client {}", success ? "succeeded" : "failed", clientId);
```

4. **Audit existing log statements.** Search the codebase for logger calls that mention credential variable names and review each one.

5. **Configure log scrubbing.** Use a log appender or pipeline filter (e.g., Logback's `ReplacingCompositeConverter`, or a SIEM ingestion rule) as a defence-in-depth measure, but do not rely on scrubbing as a substitute for fixing the source.

## References

- [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OWASP Java Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Java_Security_Cheat_Sheet.html)
- [MITRE ATT&CK T1552 – Unsecured Credentials](https://attack.mitre.org/techniques/T1552/)
- [SLF4J Best Practices](https://www.slf4j.org/manual.html)
