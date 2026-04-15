---
title: "VNX-DOCKER-002 – Dockerfile FROM :latest Tag"
description: "Detects Dockerfile FROM instructions that use the :latest tag or no tag at all, making builds non-reproducible and vulnerable to silent supply chain compromise."
---

## Overview

This rule detects `FROM` instructions in Dockerfiles that use the `:latest` tag (explicitly or implicitly by omitting a tag entirely) without also pinning via a digest (`@sha256:`). Using `:latest` means your build pulls whatever image is currently tagged latest in the registry at build time — a value that can change at any moment. This makes builds non-reproducible and creates a supply chain attack vector where a compromised or maliciously updated base image is silently incorporated into your container. This maps to CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

**Severity:** Medium | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

Supply chain attacks against container base images have increased sharply. The 2020 SolarWinds compromise, the 2021 Codecov breach, and repeated incidents on Docker Hub involving typosquatted or hijacked images all demonstrate that attackers target the dependency supply chain as a reliable path into downstream systems. When you pin to `:latest`, you have no way to detect that a new base image was silently introduced into your build.

Beyond security, unpinned base images cause operational problems: a breaking change in the upstream image (a removed package, a changed default locale, a new OpenSSL version) can fail your build or change runtime behavior with no clear signal. Teams commonly discover this at 2 AM when a previously working CI pipeline suddenly fails after an upstream maintainer pushed a new `:latest`.

CAPEC-185 (Malicious Software Update) covers the attack class, and MITRE ATT&CK T1195.002 (Compromise Software Supply Chain) maps to the scenario where a base image registry is compromised.

## What Gets Flagged

The rule flags any `FROM` line that either explicitly uses `:latest` or contains no `:tag` or `@sha256:` specifier:

```dockerfile
# FLAGGED: explicit :latest tag
FROM node:latest

# FLAGGED: no tag at all (implicitly :latest)
FROM ubuntu

# FLAGGED: multi-stage build with untagged base
FROM python AS builder
```

The rule does not flag `FROM scratch` (intentionally untagged for empty base images).

## Remediation

1. **Pin to a specific version tag at minimum.** Replace `:latest` with a concrete version number. This ensures your build reproducibly uses a known base image version.

   ```dockerfile
   # BETTER: specific version tag
   FROM node:22.2.0-alpine3.20
   ```

2. **Pin to a SHA-256 digest for maximum security.** A version tag like `node:22.2.0` can be re-tagged by the maintainer; a digest pin is immutable. Retrieve the digest with `docker pull` or `docker buildx imagetools inspect` and embed it in the `FROM`.

   ```dockerfile
   # SAFE: version tag plus immutable digest pin
   FROM node:22.2.0-alpine3.20@sha256:a1b2c3d4e5f6...

   # SAFE: digest-only pin (maximum immutability)
   FROM ubuntu@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed3c...
   ```

3. **Use a dependency update tool to keep pins current.** Pinning to a specific digest solves reproducibility but requires a workflow to receive upstream security patches. Use Dependabot, Renovate Bot, or `docker pull --quiet && docker inspect --format='{{index .RepoDigests 0}}'` in a scheduled CI job to propose updated digest pins.

4. **For multi-stage builds, pin every stage.** Each `FROM` in a multi-stage Dockerfile is an independent base image fetch and must be pinned individually.

   ```dockerfile
   # SAFE: all stages pinned
   FROM golang:1.22.3-alpine3.19@sha256:abc123... AS builder
   RUN go build -o /app ./cmd/app

   FROM gcr.io/distroless/static-debian12@sha256:def456...
   COPY --from=builder /app /app
   ENTRYPOINT ["/app"]
   ```

5. **Use a private registry mirror with image promotion.** For enterprise environments, pull images into a private registry after security scanning, and reference that registry in your Dockerfiles. This ensures all images pass your security gate before use.

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [CAPEC-185: Malicious Software Update](https://capec.mitre.org/data/definitions/185.html)
- [MITRE ATT&CK T1195.002 – Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [CIS Docker Benchmark v1.6 – Control 4.6 (Ensure images are scanned)](https://www.cisecurity.org/benchmark/docker)
- [Docker documentation – Specify a digest](https://docs.docker.com/reference/dockerfile/#from)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Renovate Bot – Automated dependency updates including Docker digests](https://docs.renovatebot.com/modules/manager/dockerfile/)
