---
title: "VNX-1052 – Hard-coded Endpoint in Datastore Client Initialization"
description: "Detects database, cache and message-broker clients in Go, Java, JavaScript/TypeScript, PHP and Python initialised with a hard-coded non-loopback IP address or host name."
---

## Overview

VNX-1052 reports a database, cache or broker client that is initialised with a **hard-coded network endpoint**: a non-loopback IP address or a real host name written as a literal ([CWE-1052](https://cwe.mitre.org/data/definitions/1052.html), a hard-coded literal used in initialization). It recognises:

- a connection URI that starts a string literal: `mysql://`, `postgres://`, `mongodb://`, `redis://`, `amqp://`, `jdbc:<driver>://`, `jdbc:oracle:thin:@`;
- a key=value DSN with `host=` or `server=` (PDO `mysql:host=...`, libpq `host=...`);
- a `host`/`addr`/`server` field or keyword argument inside a client constructor (`redis.Options{Addr: ...}`, `psycopg2.connect(host=...)`, `mysql.createPool({ host: ... })`);
- the host as the first argument of `new Jedis`, `new MongoClient`, `new mysqli`, `mysqli_connect`, `redis.Redis`, `grpc.Dial`.

**Severity:** Low | **CWE:** [CWE-1052](https://cwe.mitre.org/data/definitions/1052.html)

## Why This Matters

An endpoint written into the code cannot change without a release, ships the internal network layout to everyone who can read the source, and is usually where the credentials sit next to it. Configuration that differs between environments belongs in configuration.

## What Gets Flagged

```go
rdb := redis.NewClient(&redis.Options{
	Addr: "10.20.0.7:6379", // FLAGGED
})
sql.Open("postgres", "host=db-primary.acme-corp.net port=5432 user=app") // FLAGGED
```

```java
DriverManager.getConnection("jdbc:mysql://10.0.4.12:3306/orders", user, secret); // FLAGGED
new Jedis("cache01.prod.acme.io", 6379); // FLAGGED
```

```php
new PDO('mysql:host=10.0.0.21;dbname=shop', $user, $pass); // FLAGGED
```

## What Is Not Flagged

- `localhost`, `127.x`, `0.0.0.0`, `::1` and placeholder domains (`example.com`, `.test`, `.invalid`, `.local`).
- A literal on a line that reads the environment or configuration, where it is only a fallback: `process.env.DB_HOST || 'db.acme.net'`, `os.environ.get("DATABASE_URL", "postgres://...")`.
- Single-label service names (`host="db"`), a URI inside a longer log message, comments, test files, and host-like values outside a client constructor.

Credentials inside connection strings are reported by the connection-string rules (VNX-SEC-008, VNX-SEC-061).

## Remediation

Read the endpoint from configuration or the environment (`os.Getenv("REDIS_ADDR")`, `process.env.DATABASE_URL`, Spring `spring.datasource.url`) and keep per-environment values out of the source tree.

## References

- [CWE-1052: Excessive Use of Hard-Coded Literals in Initialization](https://cwe.mitre.org/data/definitions/1052.html)
