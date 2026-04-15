---
title: "VNX-DOCKER-004 – Dockerfile ADD with Remote URL"
description: "Detects Dockerfile ADD instructions that download content from HTTP or HTTPS URLs, bypassing integrity verification and creating a supply chain attack vector."
---

## Overview

This rule detects `ADD` instructions in Dockerfiles that download content directly from an HTTP or HTTPS URL (e.g., `ADD https://example.com/tool.tar.gz /usr/local/`). While Docker's `ADD` instruction supports URL downloads, it performs no checksum or signature verification of the downloaded content — the build silently accepts whatever bytes the server returns. This creates a supply chain attack vector where a compromised server, a DNS hijack, or a BGP rerouting can substitute malicious content without any build-time detection. This maps to CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

**Severity:** Medium | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

When `ADD` fetches from a URL, the Docker daemon connects to that URL at build time and copies the response body into the image layer. There is no built-in mechanism to verify:

- That the content is the same as when you last built the image
- That the server has not been compromised between builds
- That the URL has not been redirected to a malicious host

This is exactly the attack surface exploited in the 2020 SolarWinds attack and the Codecov supply chain breach: a trusted URL serves tampered content that is incorporated into builds without triggering any alerts. CAPEC-185 (Malicious Software Update) and MITRE ATT&CK T1195.002 (Compromise Software Supply Chain) document this class of attack.

The Docker documentation itself discourages using `ADD` with URLs, explicitly recommending `curl` or `wget` with checksum verification instead.

## What Gets Flagged

The rule matches any `ADD` instruction where the source argument begins with `http://` or `https://`:

```dockerfile
# FLAGGED: ADD fetching binary from remote URL — no integrity check
ADD https://example.com/myapp-v1.2.tar.gz /opt/myapp/

# FLAGGED: ADD fetching installer script — trivially tamperable
ADD https://get.example.com/install.sh /tmp/install.sh
```

## Remediation

1. **Replace `ADD <url>` with a `RUN` step using `curl` or `wget` that downloads the file and immediately verifies its SHA-256 checksum.** Obtain the expected checksum from the tool vendor's release page and embed it directly in the Dockerfile.

   ```dockerfile
   # SAFE: download and verify checksum before use
   FROM debian:12-slim

   RUN set -eux; \
       curl -fsSL https://example.com/myapp-v1.2.tar.gz -o /tmp/myapp.tar.gz; \
       echo "a1b2c3d4e5f6...expectedhash  /tmp/myapp.tar.gz" | sha256sum -c -; \
       tar -xzf /tmp/myapp.tar.gz -C /opt/myapp/; \
       rm /tmp/myapp.tar.gz
   ```

2. **Prefer GPG signature verification where available.** For tools that publish a `.asc` or `.sig` alongside their release artifacts, verify the GPG signature instead of (or in addition to) the SHA-256 hash. This adds a trust anchor that a checksum alone does not provide.

   ```dockerfile
   # SAFE: GPG signature verification
   FROM debian:12-slim

   RUN set -eux; \
       gpg --keyserver keys.openpgp.org --recv-keys ABCDEF1234567890; \
       curl -fsSL https://example.com/myapp-v1.2.tar.gz -o /tmp/myapp.tar.gz; \
       curl -fsSL https://example.com/myapp-v1.2.tar.gz.asc -o /tmp/myapp.tar.gz.asc; \
       gpg --verify /tmp/myapp.tar.gz.asc /tmp/myapp.tar.gz; \
       tar -xzf /tmp/myapp.tar.gz -C /opt/myapp/
   ```

3. **Copy files from a build context or a verified prior stage.** If the tool is versioned and regularly updated, consider vendoring its binary into your repository or fetching it in a dedicated CI job that validates the checksum before making it available to Dockerfile builds.

   ```dockerfile
   # SAFE: multi-stage build — tool verified and copied from a trusted earlier stage
   FROM debian:12-slim AS downloader
   RUN curl -fsSL https://example.com/tool -o /tool \
       && echo "expectedhash  /tool" | sha256sum -c -

   FROM gcr.io/distroless/static-debian12
   COPY --from=downloader /tool /usr/local/bin/tool
   ```

4. **Use BuildKit with `--checksum` (Docker 24.0+).** Newer versions of Docker BuildKit support a `--checksum` option on `ADD` for URL sources, allowing you to specify an expected SHA-256 digest directly in the `ADD` instruction.

   ```dockerfile
   # SAFE: ADD with explicit checksum (BuildKit 24.0+)
   # syntax=docker/dockerfile:1
   ADD --checksum=sha256:a1b2c3... https://example.com/myapp.tar.gz /opt/myapp/
   ```

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [CAPEC-185: Malicious Software Update](https://capec.mitre.org/data/definitions/185.html)
- [MITRE ATT&CK T1195.002 – Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
- [Docker documentation – ADD instruction](https://docs.docker.com/reference/dockerfile/#add)
- [Docker documentation – ADD with checksum (BuildKit)](https://docs.docker.com/reference/dockerfile/#add---checksum)
- [CIS Docker Benchmark v1.6](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
