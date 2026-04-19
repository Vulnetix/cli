---
title: "VNX-1052 – Excessive Resource Usage"
description: "Detects sleep and delay functions across Go, Java, Node.js, and Python that may indicate uncontrolled blocking, unbounded delays, or denial-of-service vectors."
---

## Overview

VNX-1052 is an auto-generated broad-pattern rule that searches for sleep and delay primitives across Go, Java, Node.js, and Python source files. The rule targets `time.Sleep` in Go, `Thread.sleep` in Java, `setTimeout` in Node.js, and `time.sleep` in Python. These are associated with [CWE-1052](https://cwe.mitre.org/data/definitions/1052.html) in the rule metadata.

Note: CWE-1052 in MITRE's catalog covers "Excessive Use of Hard-Coded Literals in Initialization." The resource concern this rule addresses — uncontrolled blocking delays — maps more precisely to [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html). The CWE mapping is a known limitation of this auto-generated rule.

Sleep functions are widely used for legitimate purposes (rate limiting, polling backoff, animation). Findings must be reviewed in context to determine whether the sleep duration or scheduling is controlled by user input, or whether blocking calls can exhaust thread or goroutine pools.

**Severity:** Medium | **CWE:** [CWE-1052](https://cwe.mitre.org/data/definitions/1052.html) | **OWASP:** [A04:2021 – Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)

## Why This Matters

When sleep durations are derived from user-supplied input, an attacker can trigger arbitrarily long blocking operations. In thread-per-request server models, a small number of requests that each sleep for a long duration can exhaust the thread pool and deny service to legitimate users.

Even with fixed sleep durations, busy-wait patterns and synchronous blocking in event loops (Node.js) or goroutine-heavy servers (Go) can degrade performance significantly under load. Identifying all blocking delay usage enables an architectural review of whether async alternatives are appropriate.

## What Gets Flagged

The rule scans Go, Java, Node.js, and Python source files for sleep and delay patterns:

```python
# FLAGGED: Python sleep with user-controlled duration
import time
time.sleep(int(request.args.get('delay', 1)))
```

```go
// FLAGGED: Go time.Sleep in request handler
func handler(w http.ResponseWriter, r *http.Request) {
    time.Sleep(5 * time.Second)
}
```

```javascript
// FLAGGED: Node.js setTimeout used synchronously in async path
await new Promise(resolve => setTimeout(resolve, userDelay));
```

## Remediation

1. Never derive sleep durations from user-supplied input. Use fixed, configuration-controlled delays.
2. Enforce a maximum delay cap if configurable delays are necessary, and validate that user-supplied values do not exceed it.
3. Prefer non-blocking async patterns over thread-blocking sleeps in server contexts:
   - **Node.js**: use `setTimeout`/`setInterval` with callbacks rather than blocking the event loop.
   - **Go**: use `time.After` or `context.WithTimeout` rather than sleeping in a goroutine that holds shared resources.
4. Implement exponential backoff with jitter and a maximum cap for retry loops rather than fixed sleeps.
5. Monitor request latency distributions to detect abnormal spikes caused by unintended blocking.

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [CWE-1052: Excessive Use of Hard-Coded Literals in Initialization](https://cwe.mitre.org/data/definitions/1052.html)
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)
- [AWS Well-Architected: Retry with Jitter and Backoff](https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/)
