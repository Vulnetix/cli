---
title: "VNX-DOCKER-008 – Dockerfile Package Manager Install Without Version Pinning"
description: "Detects apt-get install, apk add, or yum install instructions in Dockerfiles that do not pin package versions, making builds non-reproducible and introducing supply chain risk."
---

## Overview

This rule flags `apt-get install`, `apk add`, and `yum install` instructions in Dockerfiles that install packages without specifying an exact version. When package versions are not pinned, each build resolves the latest available version from the mirror at build time. This means two builds from identical source code and the same Dockerfile can produce images with different package versions, making builds non-reproducible and allowing silently updated dependencies to introduce vulnerabilities or breaking changes. This maps to CWE-1357 (Reliance on Insufficiently Trustworthy Component).

This is a supply chain risk: a compromised mirror or a package maintainer's inadvertent breaking change can propagate into production images without any source code change being visible in version control. Pinned versions ensure that the exact binary that was reviewed and tested is the one that ships in production images, and that any change to a dependency version is explicit and reviewable.

The rule checks for the absence of `=` in the package install argument, which is the pinning syntax for both `apt-get` (`pkg=1.2.3-4`) and `apk` (`pkg=1.2.3`). Commented-out lines are excluded to avoid false positives on documentation or disabled instructions.

**Severity:** Low | **CWE:** [CWE-1357 – Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)

## Why This Matters

Package managers resolve unversioned install requests at build time against whatever is currently published in the package repository. An attacker who can influence that repository — through a compromised mirror, a typosquatting attack, or a dependency confusion attack — can serve a malicious package version to any Dockerfile that does not specify an exact version. CAPEC-538 (Open-Source Library Manipulation) and MITRE ATT&CK T1195.001 (Compromise Software Dependencies and Development Tools) document this class of attack.

Beyond active attacks, unversioned installs mean that a security scan of an image built today may not flag an issue that was present in an image built last week, because the packages are different. This makes vulnerability management across image versions significantly harder. Pinning versions also means that when a CVE is published for a specific package version, you can immediately determine which of your images are affected by searching for that version string in your Dockerfiles rather than having to re-scan every image.

## What Gets Flagged

```dockerfile
# FLAGGED: apt-get install without version pins
RUN apt-get update && apt-get install -y curl wget openssl

# FLAGGED: apk add without version pins
RUN apk add --no-cache git ca-certificates
```

## Remediation

1. **Pin all packages to exact versions using the package manager's version syntax.** Run the build once with unpinned packages, inspect the installed versions with `dpkg -l` or `apk info`, and then embed those version strings in the Dockerfile.

   ```dockerfile
   # SAFE: apt-get with pinned versions
   FROM debian:12-slim
   RUN apt-get update \
       && apt-get install -y --no-install-recommends \
           curl=7.88.1-10+deb12u5 \
           ca-certificates=20230311 \
       && rm -rf /var/lib/apt/lists/*
   ```

   ```dockerfile
   # SAFE: apk add with pinned versions
   FROM alpine:3.19
   RUN apk add --no-cache \
       git=2.43.0-r0 \
       ca-certificates=20230506-r0
   ```

2. **Use a pinned base image digest alongside pinned packages** to fully lock the build environment. Combine `FROM image@sha256:...` with version-pinned installs for the strongest reproducibility guarantee.

3. **Automate version updates with Dependabot or Renovate.** Both tools can parse Dockerfile `RUN` instructions and open pull requests when newer versions of pinned packages are released, balancing reproducibility with timely security updates.

## References

- [CWE-1357: Reliance on Insufficiently Trustworthy Component](https://cwe.mitre.org/data/definitions/1357.html)
- [CAPEC-538: Open-Source Library Manipulation](https://capec.mitre.org/data/definitions/538.html)
- [MITRE ATT&CK T1195.001 – Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)
- [Docker best practices – Package manager version pinning](https://docs.docker.com/build/building/best-practices/#apt-get)
- [CIS Docker Benchmark v1.6](https://www.cisecurity.org/benchmark/docker)
- [hadolint DL3008 – Pin versions in apt-get install](https://github.com/hadolint/hadolint/wiki/DL3008)
- [hadolint DL3018 – Pin versions in apk add](https://github.com/hadolint/hadolint/wiki/DL3018)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
