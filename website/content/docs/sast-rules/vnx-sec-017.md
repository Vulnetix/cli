---
title: "VNX-SEC-017 – Plaintext Protocol URL"
description: "Detects unencrypted protocol URLs (redis://, amqp://, ftp://, telnet://, ldap://) in source code, which transmit data and credentials in cleartext over the network."
---

## Overview

This rule detects connection URLs using unencrypted protocol schemes — `redis://`, `amqp://`, `ftp://`, `telnet://`, and `ldap://` — in source files. These protocols transmit all data, including authentication credentials, in cleartext. Anyone with the ability to observe network traffic between your application and the target service can intercept passwords, read data payloads, and replay or modify messages. Each of these protocols has a secure TLS-wrapped equivalent that should be used instead.

**Severity:** Medium | **CWE:** [CWE-319 – Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

## Why This Matters

The assumption that internal network traffic is "safe" from interception has been repeatedly invalidated. Cloud environments, microservice meshes, and containerized workloads share physical and virtual network infrastructure. A compromised container, a misconfigured cloud security group, or a lateral-movement foothold can put an attacker in a position to sniff internal traffic. Technologies like ARP spoofing, BGP hijacking, and compromised network devices have all been used to intercept "internal" traffic.

Specific protocol risks:
- **redis://** — Redis AUTH passwords transmitted in plaintext; session data or queue contents readable
- **amqp://** — RabbitMQ credentials and message payloads exposed; business logic data readable
- **ftp://** — Username, password, and file contents all transmitted in cleartext; replaced by FTPS or SFTP
- **telnet://** — All terminal input including passwords transmitted in cleartext; replaced by SSH
- **ldap://** — Directory queries and BIND credentials (usernames/passwords) transmitted in cleartext; replaced by LDAPS

## What Gets Flagged

```python
# FLAGGED: plaintext Redis connection
import redis

r = redis.from_url("redis://user:password@redis.example.com:6379/0")
```

```python
# FLAGGED: plaintext AMQP (RabbitMQ) connection
import pika

params = pika.URLParameters("amqp://guest:guest@rabbitmq.example.com:5672/")
connection = pika.BlockingConnection(params)
```

```yaml
# FLAGGED: LDAP without TLS in config
auth:
  ldap_url: "ldap://ldap.corp.example.com:389"
```

## Remediation

Replace each plaintext protocol with its TLS-encrypted equivalent:

| Plaintext | Encrypted | Notes |
|-----------|-----------|-------|
| `redis://` | `rediss://` | Note the double `s` |
| `amqp://` | `amqps://` | RabbitMQ supports TLS natively |
| `ftp://` | `ftps://` or `sftp://` | Prefer SFTP (SSH-based) |
| `telnet://` | `ssh://` | Telnet is completely obsolete |
| `ldap://` | `ldaps://` | Or use LDAP+STARTTLS |

```python
# SAFE: encrypted Redis connection
import redis

r = redis.from_url("rediss://user:password@redis.example.com:6380/0")
# Or use SSL parameters
r = redis.Redis(
    host=os.environ['REDIS_HOST'],
    port=6380,
    password=os.environ['REDIS_PASSWORD'],
    ssl=True,
    ssl_cert_reqs='required',
)
```

```python
# SAFE: encrypted AMQP connection (RabbitMQ with TLS)
import pika
import ssl

ssl_context = ssl.create_default_context()
ssl_context.load_verify_locations('/etc/ssl/certs/ca-certificates.crt')

params = pika.URLParameters("amqps://user:pass@rabbitmq.example.com:5671/")
connection = pika.BlockingConnection(params)
```

```yaml
# SAFE: LDAPS in config
auth:
  ldap_url: "ldaps://ldap.corp.example.com:636"
```

**For legacy systems that do not support TLS natively**, use stunnel as a TLS proxy to wrap the connection without modifying the application:

```ini
# stunnel.conf — wrap Redis in TLS
[redis-tls]
client = yes
accept = 127.0.0.1:6379
connect = redis.example.com:6380
```

The application then connects to `redis://127.0.0.1:6379` locally, and stunnel handles TLS to the actual server.

**Load connection URLs from environment variables** so that switching between environments does not require code changes:

```python
# SAFE: URL from environment variable — use rediss:// in the secret
import os, redis

r = redis.from_url(os.environ['REDIS_URL'])
```

## References

- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [OWASP: Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Redis: TLS support](https://redis.io/docs/management/security/encryption/)
- [RabbitMQ: TLS support](https://www.rabbitmq.com/ssl.html)
- [stunnel: TLS proxy](https://www.stunnel.org/)
- [MITRE ATT&CK T1040 – Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [CAPEC-157: Sniffing Attacks](https://capec.mitre.org/data/definitions/157.html)
