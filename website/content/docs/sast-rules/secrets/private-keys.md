---
title: "Secrets — Private Keys & Certificates"
description: "RSA, EC, OpenSSH, PGP, WireGuard, age and other private-key material."
weight: 10
---

RSA, EC, OpenSSH, PGP, WireGuard, age and other private-key material.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-641"></a>VNX-SEC-641 | OpenSSH private key block | Critical | keyword + regex |
| <a id="vnx-sec-642"></a>VNX-SEC-642 | RSA private key block | Critical | keyword + regex |
| <a id="vnx-sec-643"></a>VNX-SEC-643 | EC private key block | Critical | keyword + regex |
| <a id="vnx-sec-644"></a>VNX-SEC-644 | DSA private key block | Critical | keyword + regex |
| <a id="vnx-sec-645"></a>VNX-SEC-645 | PKCS8 private key block | Critical | keyword + regex |
| <a id="vnx-sec-646"></a>VNX-SEC-646 | Encrypted private key block | High | keyword + regex |
| <a id="vnx-sec-647"></a>VNX-SEC-647 | PuTTY private key file (.ppk) | Critical | keyword + regex |
| <a id="vnx-sec-648"></a>VNX-SEC-648 | SSH2 private key block | Critical | keyword + regex |
| <a id="vnx-sec-649"></a>VNX-SEC-649 | PKCS12 keystore reference | High | keyword + regex + entropy |
| <a id="vnx-sec-650"></a>VNX-SEC-650 | Certificate bundled with private key | Medium | keyword + regex |
| <a id="vnx-sec-651"></a>VNX-SEC-651 | JWT HS256 hardcoded signing secret | Critical | keyword + regex + entropy |
| <a id="vnx-sec-697"></a>VNX-SEC-697 | SSH private key beginning marker (generic) | Critical | keyword + regex |
| <a id="vnx-sec-731"></a>VNX-SEC-731 | Hardcoded session/cookie signing secret | High | keyword + regex + entropy |
| <a id="vnx-sec-732"></a>VNX-SEC-732 | Hardcoded encryption key (AES/Fernet context) | High | keyword + regex + entropy |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
