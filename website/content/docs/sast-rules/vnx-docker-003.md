---
title: "VNX-DOCKER-003 – Secret in Dockerfile ARG or ENV"
description: "Detects Dockerfile ARG and ENV instructions whose names suggest credentials (PASSWORD, SECRET, TOKEN, KEY, CREDENTIAL, API_KEY) and include an assigned value, baking secrets into image layers."
---

## Overview

This rule detects `ARG` and `ENV` instructions in Dockerfiles whose variable names contain credential-related keywords (`PASSWORD`, `SECRET`, `TOKEN`, `KEY`, `CREDENTIAL`, `API_KEY`) and include an assigned value. When a secret is set via `ARG foo=value` or `ENV BAR=value`, that value is baked into one or more image layers and is permanently readable from the image's history — even after subsequent `RUN unset` commands or layer overwrites. This maps to CWE-798 (Use of Hard-coded Credentials).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Docker image layers are content-addressed and immutable. Every `RUN`, `COPY`, and `ENV` instruction creates a new layer, and all layers — including intermediate ones — are stored in the image manifest. Running `docker history --no-trunc <image>` or `docker inspect` reveals the full build-time arguments and environment variables from every layer. This means that `ENV DATABASE_PASSWORD=s3cr3t` will be visible to anyone who can pull the image, including read-only registry users, CI pipelines, and — critically — in the event of a registry breach.

This is not a theoretical risk: multiple public Docker Hub repositories have been found with embedded AWS keys, database passwords, and OAuth tokens visible in image history. The 2019 Docker Hub breach exposed data for approximately 190,000 accounts, and any repositories containing credentials in image history were fully compromised.

CAPEC-191 (Read Sensitive Constants Within an Executable) captures the inspection attack, and MITRE ATT&CK T1552.001 (Credentials in Files) covers the persistence of secrets in build artifacts.

## What Gets Flagged

The rule matches `ARG` or `ENV` lines where the variable name contains a credential keyword and the line includes a value assignment:

```dockerfile
# FLAGGED: API key baked into image layer
ENV API_KEY=sk-prod-abc123def456

# FLAGGED: database password as build argument with default value
ARG DATABASE_PASSWORD=supersecret

# FLAGGED: secret token in ENV
ENV GITHUB_TOKEN=ghp_abcdefghijklmn
```

## Remediation

1. **Never pass secret values as build-time ARG defaults or ENV values.** Secrets must be injected at runtime, not baked at build time.

2. **Use Docker BuildKit's `--secret` mount for build-time secrets.** The `--secret` flag mounts a secret into a specific `RUN` step without it appearing in any layer or in `docker history`.

   ```dockerfile
   # SAFE: BuildKit secret mount — not stored in any layer
   # syntax=docker/dockerfile:1
   FROM alpine:3.20

   RUN --mount=type=secret,id=api_key \
       API_KEY=$(cat /run/secrets/api_key) \
       && curl -H "Authorization: Bearer $API_KEY" https://api.example.com/setup
   ```

   Build with:
   ```bash
   docker build --secret id=api_key,src=./api_key.txt .
   ```

3. **Pass secrets at runtime as environment variables, not build time.** Define the variable name in the Dockerfile without a value; the orchestrator (Kubernetes, Docker Compose, ECS) injects the actual value at container startup.

   ```dockerfile
   # SAFE: variable name declared, no value baked in
   FROM node:22.2.0-alpine3.20

   # Do NOT set: ENV DATABASE_PASSWORD=...
   # Instead, expect DATABASE_PASSWORD to be set by the container runtime

   CMD ["node", "server.js"]
   ```

   ```yaml
   # Kubernetes secret injection (SAFE)
   env:
     - name: DATABASE_PASSWORD
       valueFrom:
         secretKeyRef:
           name: db-secret
           key: password
   ```

4. **Use a secrets manager at runtime.** Applications should fetch secrets from AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, or GCP Secret Manager at startup rather than relying on environment variables for sensitive values.

5. **Scan your images before pushing.** Tools like `truffleHog`, `gitleaks`, and `docker scan` can detect secrets in image history. Add this step to your CI pipeline before the push step.

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CAPEC-191: Read Sensitive Constants Within an Executable](https://capec.mitre.org/data/definitions/191.html)
- [MITRE ATT&CK T1552.001 – Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [Docker documentation – Build secrets](https://docs.docker.com/build/building/secrets/)
- [CIS Docker Benchmark v1.6 – Sensitive information in Dockerfiles](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet – Secrets](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
