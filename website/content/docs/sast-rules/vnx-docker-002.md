---
title: "VNX-DOCKER-002 – Dockerfile FROM :latest Tag"
description: "Detects Dockerfile FROM instructions that use the :latest tag or no tag at all, making builds non-reproducible and vulnerable to silent supply chain compromise."
---

## Overview

This rule detects `FROM` instructions in Dockerfiles that use the `:latest` tag (explicitly or implicitly by omitting a tag entirely) without also pinning via a digest (`@sha256:`). Using `:latest` means your build pulls whatever image is currently tagged latest in the registry at build time — a value that can change at any moment. This makes builds non-reproducible and creates a supply chain attack vector where a compromised or maliciously updated base image is silently incorporated into your container without any visible change to the Dockerfile. This maps to CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

**Default behaviour:** `:latest` is the Docker default when no tag is specified. You must explicitly opt in to a pinned version or digest.

**Severity:** Medium | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) | **CIS Docker Benchmark:** Control 4.6

## Why This Matters

Supply chain attacks against container base images have increased sharply. The 2020 SolarWinds compromise and the 2021 Codecov breach both demonstrated that attackers target the dependency supply chain as a reliable path into downstream systems. Repeated incidents on Docker Hub involving typosquatted or hijacked images have shown that when you pin to `:latest`, you have no way to detect that a new base image was silently incorporated into your build.

CAPEC-185 (Malicious Software Update) and MITRE ATT&CK T1195.002 (Compromise Software Supply Chain) map to the scenario where a base image registry is compromised and a new `:latest` containing a backdoor is pushed. Any downstream build that uses `FROM ubuntu:latest` or `FROM ubuntu` without a digest will silently incorporate the malicious image on next build.

Beyond security, unpinned base images cause operational failures: a breaking change in the upstream image (a removed package, a changed default locale, a new library soname) can fail your build or alter runtime behaviour with no clear signal. Teams commonly discover this at 2 AM when a previously working CI pipeline fails after an upstream maintainer pushed a new `:latest`.

## What Gets Flagged

The rule flags any `FROM` line that either explicitly uses `:latest` or contains no `:tag` or `@sha256:` specifier. `FROM scratch` is intentionally excluded — scratch is the conventional empty base and the lack of a tag is meaningful.

```dockerfile
# FLAGGED: explicit :latest tag
FROM node:latest

# FLAGGED: no tag at all (resolves to :latest implicitly)
FROM ubuntu

# FLAGGED: multi-stage build with untagged base
FROM python AS builder

# NOT FLAGGED: digest pin is immutable
FROM ubuntu@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed3c...

# NOT FLAGGED: intentional empty base
FROM scratch
```

## Remediation

**Pin to a specific version tag at minimum.** Replace `:latest` with a concrete version number. This ensures your build reproducibly uses a known base image version.

```dockerfile
# BETTER: specific version tag
FROM node:22.2.0-alpine3.20
```

**Pin to a SHA-256 digest for maximum security.** A version tag like `node:22.2.0` can be re-tagged by the maintainer; a digest pin is immutable and cryptographically guaranteed. Retrieve the digest with `docker buildx imagetools inspect` and embed it directly in the `FROM` instruction.

```dockerfile
# SAFE: version tag plus immutable digest pin
FROM node:22.2.0-alpine3.20@sha256:a1b2c3d4e5f6...

# SAFE: digest-only pin (maximum immutability)
FROM ubuntu@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed3c...
```

**Pin every stage in a multi-stage build.** Each `FROM` in a multi-stage Dockerfile is an independent base image fetch and must be pinned individually:

```dockerfile
# SAFE: all stages pinned with version tags and digests
FROM golang:1.22.3-alpine3.19@sha256:abc123... AS builder
RUN go build -o /app ./cmd/app

FROM gcr.io/distroless/static-debian12@sha256:def456...
COPY --from=builder /app /app
ENTRYPOINT ["/app"]
```

**Use a dependency update tool to keep pins current.** Pinning to a specific digest solves reproducibility but requires a workflow to receive upstream security patches. Dependabot and Renovate Bot both support Dockerfile digest pinning and will open pull requests when upstream images are updated, balancing immutability with timely security fixes.

**For enterprise environments**, pull images into a private registry after security scanning and reference that registry in your Dockerfiles. This ensures all images pass your security gate before use, regardless of upstream registry availability.

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [CAPEC-185: Malicious Software Update](https://capec.mitre.org/data/definitions/185.html)
- [MITRE ATT&CK T1195.002 – Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [CIS Docker Benchmark v1.6 – Control 4.6: Ensure images are scanned and rebuilt frequently](https://www.cisecurity.org/benchmark/docker)
- [Docker Reference – FROM instruction](https://docs.docker.com/reference/dockerfile/#from)
- [Docker Build Best Practices – Pin base image versions](https://docs.docker.com/build/building/best-practices/#from)
- [OWASP Docker Security Cheat Sheet – Pin base image versions](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Renovate Bot – Automated Dockerfile digest updates](https://docs.renovatebot.com/modules/manager/dockerfile/)
- [hadolint DL3007 – Using latest is best avoided](https://github.com/hadolint/hadolint/wiki/DL3007)
