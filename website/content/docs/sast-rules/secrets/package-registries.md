---
title: "Secrets — Package Registries"
description: "npm, PyPI, RubyGems, NuGet, Artifactory, Crates and other registry tokens."
weight: 6
---

npm, PyPI, RubyGems, NuGet, Artifactory, Crates and other registry tokens.

All rules in this category are kind `secrets`. They run under `vulnetix secrets` and the secrets stage of `vulnetix scan`.

| Rule ID | Name | Severity | Detection |
|---------|------|----------|-----------|
| <a id="vnx-sec-098"></a>VNX-SEC-098 | Crates.io (Rust) API token | Critical | keyword + regex + entropy |

## Remediation

Rotate any exposed credential immediately, remove it from source, and load it from a secrets manager or environment variable instead. Purge it from git history with `git filter-repo`. See [CWE-798](https://cwe.mitre.org/data/definitions/798.html) and the [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html).
