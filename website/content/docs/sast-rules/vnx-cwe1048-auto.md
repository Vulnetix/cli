---
title: "VNX-1048 – Function with a Large Number of Outward Calls"
description: "Detects a single function or method in Go, Java, JavaScript/TypeScript, PHP, Python or Ruby whose body calls 40 or more distinct functions or methods (excessive fan-out)."
---

## Overview

VNX-1048 reports a function or method that calls **40 or more distinct functions or methods** in its own body ([CWE-1048](https://cwe.mitre.org/data/definitions/1048.html), excessive fan-out). Each distinct callee name counts once, with its receiver, so `db.Close()` and `store.Close()` are two callees and a call repeated ten times is one. String literals and comment lines are removed before counting and language keywords (`if`, `for`, `return`, `len`, `isset`...) are ignored. In Ruby a method sent without parentheses (`account.suspended?`) counts as a call.

The body runs to the function's closing brace (Go, Java, PHP, JavaScript/TypeScript), its dedent (Python) or its `end` (Ruby), measured over at most 300 lines.

**Severity:** Low | **CWE:** [CWE-1048](https://cwe.mitre.org/data/definitions/1048.html)

## Why This Matters

A unit that reaches 40 other units does many jobs at once: it is hard to review as one, hard to test exhaustively, and a security check placed among the calls (an authorisation test, a rate limit, a fraud screen) is easy to miss, reorder or bypass when the function is edited.

## What Gets Flagged

```go
// FLAGGED: main wires config, database, cache, auth, metrics, routes and shutdown itself
func main() {
	cfg, err := config.Load(*cfgPath)
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	store := cache.NewRedis(cfg.RedisAddr)
	verifier, err := auth.NewVerifier(cfg.JWKSURL)
	// ... 40+ distinct calls
}
```

```javascript
// FLAGGED: a route handler that authenticates, checks quota, scans, stores, queues and notifies
router.post('/documents', upload.single('file'), async (req, res, next) => {
  const quota = await db.quotas.findOne({ userId: req.user.id });
  const verdict = await scanFile(req.file.path);
  await s3.putObject({ Bucket: process.env.BUCKET, Key: key, Body: buffer }).promise();
  // ... 40+ distinct calls
});
```

## What Is Not Flagged

- The same work split into helpers that each call fewer than 40 things (`validate`, `price`, `persist`, `notifyParties`).
- A long function that repeats a few calls (`out.write(format_row(...))` sixty times).
- SQL functions inside a query string or a PHP/Ruby heredoc (`COUNT(`, `COALESCE(`), and calls in comments.
- Test files, vendored or minified code, front-end libraries in `static/js/libs` and similar, AMD `define([...], function () {...})` module wrappers and whole-page DOM-ready wrappers (`$(document).ready(function () {...})`, `DOMContentLoaded` listeners).

## Remediation

Split the function by responsibility: keep the orchestration in one short function and move each step (validation, pricing, persistence, notification) into its own named function that can be read and tested alone. Keep security checks at the top of the orchestrating function where a reviewer sees them first.

## References

- [CWE-1048: Invokable Control Element with Large Number of Outward Calls](https://cwe.mitre.org/data/definitions/1048.html)
