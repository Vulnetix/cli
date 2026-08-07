---
title: Discovery
weight: 1
description: "DNS, the .well-known/tea document, endpoint selection and TEI resolution"
---


DNS, the .well-known/tea document, endpoint selection and TEI resolution

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 2 | 2 | 0 | 0 |

## Discovery

A consumer starts with a TEI, which carries a domain and nothing else. These are the
steps between that domain and an API it can call.

| Step | Result |
|---|---|
| DNS for `vulnetix.com` | 104.20.37.56, 172.66.157.213, 2606:4700:10::6814:2538, 2606:4700:10::ac42:9dd5 |
| Discovery document | `https://vulnetix.com/.well-known/tea` |
| Endpoints advertised | 1 |
| Endpoint selected | `https://www.vulnetix.com/tea` |
| Version selected | 0.4.0 |
| API root | `https://www.vulnetix.com/tea/v0.4.0` |

| Endpoint | Versions | Priority |
|---|---|---:|
| `https://www.vulnetix.com/tea` | 0.4.0 | 1.00 |

### discovery cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| discovery document conforms to tea-well-known.schema.json | `wellKnownDiscoveryDocument` | 200 | yes | 196.54 ms | pass |
| discovery document is not served over plaintext HTTP | `wellKnownDiscoveryDocument` | 200 | - | 168.83 ms | pass |


[Back to the summary](../)
