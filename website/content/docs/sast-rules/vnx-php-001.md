---
title: "VNX-PHP-001 – Missing composer.lock"
description: "Detect PHP projects that are missing a composer.lock file, leaving them vulnerable to non-deterministic dependency resolution and supply chain attacks."
---

## Overview

This rule flags PHP projects that have a `composer.json` file but no corresponding `composer.lock`. The `composer.lock` file pins every dependency — direct and transitive — to an exact version and records the download URL and cryptographic hash of each package. Without it, running `composer install` on a fresh checkout resolves floating version ranges (`^1.2`, `~3.0`) at download time, meaning two builds from the same source tree can install entirely different code. This maps to [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html).

**Severity:** High | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

Without a `composer.lock`, an attacker who can influence the Packagist registry or your private repository — through a typosquat package, a compromised maintainer account, or a dependency confusion attack — can inject malicious code into your build without ever touching your repository. The substituted package arrives as a legitimate resolved version of a floating range you declared. In CI/CD pipelines, where `composer install` is run on every push, this attack is repeatable and invisible if no integrity check exists. A poisoned Composer package can exfiltrate environment variables containing database passwords and API keys, install a web shell, or silently modify application logic. MITRE ATT&CK technique T1195.001 (Supply Chain Compromise: Compromise Software Dependencies) covers this exact attack class.

## What Gets Flagged

The rule fires when a directory is registered as containing PHP source files but the file `composer.lock` is absent from that same directory. The most common causes are: `composer.json` was committed without running `composer install` first, or `composer.lock` was excluded from version control via `.gitignore` (a practice sometimes recommended for libraries but never appropriate for applications).

```php
// FLAGGED: project directory has composer.json but no composer.lock
// $ ls
// composer.json   src/   vendor/
// (composer.lock is missing — dependencies are not pinned)
```

## Remediation

1. **Generate the lock file.** Run `composer install` in the directory containing `composer.json`. This resolves the full dependency graph, downloads packages, and writes `composer.lock` alongside the existing manifest.

```bash
composer install
```

2. **Commit `composer.lock` to version control.** The file must be in source control so every developer checkout, CI build, and deployment uses the same verified package versions.

```bash
git add composer.lock
git commit -m "chore: add composer.lock to pin dependency versions"
```

3. **Strip development dependencies from production.** When deploying to production, pass `--no-dev` to exclude packages that are only needed for testing and code quality tooling. This also shrinks the attack surface.

```bash
# SAFE: production install — locked versions, no dev packages
composer install --no-dev --optimize-autoloader
```

4. **Verify integrity before deploying.** Composer validates package hashes against the lock file automatically during install. Explicitly confirm the lock file matches the current `composer.json` in CI before the build proceeds:

```bash
composer validate --strict
composer install --no-dev
```

5. **Prevent accidental exclusion.** Check that `composer.lock` is not listed in `.gitignore`. For application repositories it should never be excluded. For library repositories (packages you publish to Packagist), it is conventional to exclude the lock file, but this only applies when your consumers install your package as a dependency — not to your library's own test and integration environment.

6. **Use `COMPOSER_MIRROR_PATH_REPOS=1`** or a private Satis mirror for internal packages. This ensures that even if Packagist is unreachable or compromised, your builds resolve packages from a source you control.

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [Composer documentation – composer.lock](https://getcomposer.org/doc/01-basic-usage.md#commit-your-composer-lock-file-to-version-control)
- [MITRE ATT&CK T1195.001 – Supply Chain Compromise: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [CAPEC-185: Malicious Software Download](https://capec.mitre.org/data/definitions/185.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
