---
title: "VNX-SEC-075 – WireGuard Private Key"
description: "Reports a literal WireGuard private or preshared key (a 32-byte base64 key) in a wg-quick configuration, or assigned to a private-key name in a WireGuard-related YAML, JSON, Nix, .env, NetworkManager, RouterOS, OpenWrt or Go file."
---

## Overview

This rule reports a literal WireGuard key, a 32-byte value in base64 (43 characters and a closing `=`), written as `PrivateKey =` or `PresharedKey =` in a wg-quick/INI configuration, or, in a file that mentions WireGuard, assigned to a `private_key`-style name (Ansible variables, sing-box JSON, Nix modules, `WIREGUARD_PRIVATE_KEY=` environment entries) or passed to `wgtypes.ParseKey()`. The key is masked in the finding's snippet.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded wireguard private key values are routinely scraped by automated bots within minutes of a public push, and then used to access the account, exfiltrate data, or pivot into downstream services. Once the credential is in git history it is permanently in third-party hands.

## What Gets Flagged

```ini
# FLAGGED: /etc/wireguard/wg0.conf
[Interface]
PrivateKey = <43 base64 characters>=

[Peer]
PublicKey = <43 base64 characters>=     # public, not flagged
PresharedKey = <43 base64 characters>=  # flagged
```

```yaml
# FLAGGED: compose environment for a WireGuard client
environment:
  - VPN_TYPE=wireguard
  - WIREGUARD_PRIVATE_KEY=<43 base64 characters>=
```

```text
# FLAGGED: NetworkManager keyfile and OpenWrt UCI
private-key=<43 base64 characters>=
	option private_key '<43 base64 characters>='
```

Not flagged:

- `PublicKey` lines, `PrivateKey = ${WG_PRIVATE_KEY}` and `wg set wg0 private-key /etc/wireguard/private.key`.
- Values that are not a well-formed key: variable names, `<placeholders>`, `AAAA...=` or `xxxx...=` runs.
- Key-shaped values under other names in files unrelated to WireGuard.
- `*.example`/`*.sample` files, Markdown, and test, fixture, vendored and generated files.

## Remediation

1. **Revoke the leaked credential** in the provider's console immediately.
2. **Replace with a short-lived alternative** — OAuth 2.0 access tokens, IAM role assumption, OIDC federation — wherever the platform supports it.
3. **Store the new credential in a secrets manager** (AWS Secrets Manager, HashiCorp Vault, GitHub Actions secrets, Doppler).
4. **Audit the provider's access logs** for activity you did not initiate between the leak and the revocation.
5. **Purge from git history** with `git filter-repo` or BFG, then re-scan with gitleaks/truffleHog to confirm no other secrets remain.
6. **Enable push protection** so future commits are blocked at the developer machine.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [truffleHog](https://github.com/trufflesecurity/trufflehog)
- [OWASP Credentials Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credentials_Management_Cheat_Sheet.html)
- [MITRE ATT&CK T1552.001 – Credentials In Files](https://attack.mitre.org/techniques/T1552/001/)
- [git-filter-repo](https://github.com/newren/git-filter-repo)
