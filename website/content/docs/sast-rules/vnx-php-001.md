---
title: "VNX-PHP-001 – Missing composer.lock"
description: "Detect PHP projects that have a composer.json but no composer.lock, leaving dependency resolution non-deterministic and the supply chain open to substitution attacks."
---

## Overview

This rule fires when a directory contains a `composer.json` manifest but no `composer.lock` file. The lock file pins every dependency — direct and transitive — to an exact version, download URL, and cryptographic hash. Without it, `composer install` on a fresh checkout resolves floating version ranges (`^1.2`, `~3.0`) against whatever the Packagist registry returns at that moment, so two builds from the same source tree can install entirely different code.

**Severity:** High | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) | **CAPEC:** [CAPEC-185](https://capec.mitre.org/data/definitions/185.html) | **ATT&CK:** [T1195.001](https://attack.mitre.org/techniques/T1195/001/)

> **PHP default behavior:** Composer does NOT enforce a lock file by default. Running `composer install` without a `composer.lock` present silently resolves versions from the registry. Commit the lock file to version control and enforce `composer install` (not `composer update`) in CI to get deterministic builds.

## Why This Matters

Without a `composer.lock`, an attacker who can influence the Packagist registry — through a typosquatted package, a compromised maintainer account, or a dependency confusion attack — can inject malicious code into your build without ever touching your repository. The substituted package arrives as a legitimately resolved version of a floating range you declared. In CI/CD pipelines where `composer install` runs on every push, this attack is repeatable and invisible unless integrity checks exist.

Real-world impact from compromised Packagist packages has included exfiltration of environment variables containing database passwords and API keys, installation of web shells, and silent modification of application logic. MITRE ATT&CK technique T1195.001 (Supply Chain Compromise: Compromise Software Dependencies) covers this exact attack class.

**OWASP ASVS v4.0 mapping:** V14.2.1 — Verify that all components are up to date, preferably using a dependency checker during build or compile time.

## What Gets Flagged

The rule fires when a directory is registered as containing PHP source files but `composer.lock` is absent from that directory. Common causes:

- `composer.json` was committed without running `composer install` first
- `composer.lock` was excluded via `.gitignore` (correct for published libraries, never correct for applications)
- A developer ran `composer update` and discarded the resulting lock file

```
// FLAGGED: project directory has composer.json but no composer.lock
// $ ls
// composer.json   src/   vendor/
// (composer.lock is missing — dependencies are resolved non-deterministically)
```

## Remediation

**1. Generate and commit the lock file.**

```bash
composer install   # resolves the graph, writes composer.lock
git add composer.lock
git commit -m "chore: add composer.lock to pin dependency versions"
```

**2. Use `composer install` (not `composer update`) in CI.** `install` reads the lock file; `update` re-resolves from the registry and rewrites it.

```bash
# SAFE: CI production install — locked versions, no dev packages
composer install --no-dev --optimize-autoloader
```

**3. Validate in CI before installing.**

```bash
composer validate --strict   # fails if composer.json is invalid or lock is stale
composer install --no-dev
```

**4. Prevent accidental exclusion.** Ensure `composer.lock` is not in `.gitignore`. For application repositories it must always be committed.

**5. Use a private Satis mirror or Composer repository for internal packages** so your builds do not rely solely on Packagist availability.

**6. Verify package hashes.** Composer automatically validates downloaded packages against the hashes stored in the lock file. Do not pass `--no-scripts` without understanding which autoload scripts you are disabling.

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [OWASP PHP Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [OWASP ASVS v4.0 – V14.2 Dependency](https://owasp.org/www-project-application-security-verification-standard/)
- [Composer documentation – commit your composer.lock](https://getcomposer.org/doc/01-basic-usage.md#commit-your-composer-lock-file-to-version-control)
- [MITRE ATT&CK T1195.001 – Supply Chain Compromise: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [CAPEC-185: Malicious Software Download](https://capec.mitre.org/data/definitions/185.html)
