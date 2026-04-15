---
title: "VNX-DOCKER-006 – Dockerfile Uses ADD Instead of COPY for Local Files"
description: "Detects ADD instructions used to copy local files or directories, where the simpler and more explicit COPY instruction should be used instead."
---

## Overview

This rule flags `ADD` instructions in Dockerfiles that copy local files or directories rather than fetching from a remote URL. Docker's `ADD` instruction has two documented behaviours beyond simple copying: it automatically extracts tar archives into the destination directory, and it can fetch content from remote HTTP or HTTPS URLs. When a developer intends only to copy a local file, using `ADD` obscures this intent and can cause silent, unexpected extraction of archives that happen to be placed in the build context. This maps to CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

The Docker documentation and every major linting tool explicitly recommend using `COPY` for local file operations. `COPY` has one clearly defined behaviour — it copies files from the build context into the image — making Dockerfiles easier to read, audit, and reason about. Using `ADD` for local files is a common habit that introduces unnecessary ambiguity.

This rule does not flag `ADD` instructions that explicitly reference an HTTP or HTTPS URL, as those are covered separately by VNX-DOCKER-004 which focuses on remote URL integrity verification.

**Severity:** Low | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

The implicit tar extraction behaviour of `ADD` creates two practical risks. First, if a `.tar`, `.tar.gz`, `.tgz`, or similar archive is placed in the build context — intentionally or as a build artefact — and an `ADD` instruction copies a directory that contains it, Docker extracts the archive into the image without any explicit instruction to do so. This can add unexpected files to the image, potentially increasing the attack surface.

Second, the dual behaviour makes security reviews harder. An auditor scanning a Dockerfile must inspect every `ADD` argument to determine whether it might perform extraction or a network fetch, whereas `COPY` is always unambiguous. Reducing cognitive load in security-critical files directly reduces the chance of an overlooked misconfiguration.

CAPEC-185 (Malicious Software Update) and MITRE ATT&CK T1195.002 (Compromise Software Supply Chain) apply when the unexpected extraction or fetch introduces content that was not intended to be in the image.

## What Gets Flagged

```dockerfile
# FLAGGED: ADD used to copy a local binary — use COPY instead
ADD myapp /usr/local/bin/myapp

# FLAGGED: ADD used to copy a directory — implicit tar extraction risk
ADD ./config/ /etc/myapp/

# FLAGGED: ADD used to copy a local archive — will be silently extracted
ADD myapp-v1.2.tar.gz /opt/myapp/
```

## Remediation

1. **Replace all `ADD` instructions that reference local paths with `COPY`.** This makes intent explicit and eliminates the implicit extraction and URL-fetch behaviours.

   ```dockerfile
   # SAFE: COPY clearly communicates intent
   FROM debian:12-slim
   COPY myapp /usr/local/bin/myapp
   COPY ./config/ /etc/myapp/
   ```

2. **If you intentionally want to extract a local archive**, use `COPY` followed by an explicit `RUN tar` step. This is verbose but unambiguous, and makes it clear in review that extraction is intentional.

   ```dockerfile
   # SAFE: explicit extraction is clear and auditable
   FROM debian:12-slim
   COPY myapp-v1.2.tar.gz /tmp/myapp.tar.gz
   RUN tar -xzf /tmp/myapp.tar.gz -C /opt/myapp/ \
       && rm /tmp/myapp.tar.gz
   ```

3. **Use `.dockerignore` to prevent accidental archives** from being included in the build context. This is a defence-in-depth measure that ensures unexpected files in your working directory do not silently end up in the image.

   ```
   # .dockerignore
   *.tar.gz
   *.tgz
   dist/
   build/
   ```

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [Docker documentation – COPY vs ADD](https://docs.docker.com/reference/dockerfile/#copy)
- [Docker best practices – Use COPY instead of ADD](https://docs.docker.com/build/building/best-practices/#add-or-copy)
- [CIS Docker Benchmark v1.6](https://www.cisecurity.org/benchmark/docker)
- [hadolint DL3020 – Use COPY instead of ADD for files and folders](https://github.com/hadolint/hadolint/wiki/DL3020)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
