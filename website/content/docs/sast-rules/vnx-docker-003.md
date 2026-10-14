---
title: "VNX-DOCKER-003 – Secret in Dockerfile ARG or ENV"
description: "Reports credential-named Dockerfile ARG and ENV instructions: ENV with a literal secret or one copied from a build arg, and any credential ARG, which persist in the image config or build history."
---

## Overview

This rule detects `ARG` and `ENV` instructions in Dockerfiles whose variable names contain credential-related keywords (`PASSWORD`, `SECRET`, `TOKEN`, `KEY`, `CREDENTIAL`, `API_KEY`) and include an assigned value. When a secret is set via `ARG foo=value` or `ENV BAR=value`, that value is baked into one or more image layers and is permanently readable from the image's history — even after subsequent `RUN unset` commands or layer overwrites. This maps to CWE-798 (Use of Hard-coded Credentials).

**Default behaviour:** Docker provides no protection for secrets placed in `ARG` or `ENV` instructions. All values are stored in image metadata and in layer history, and are accessible to anyone who can pull the image.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html) | **CIS Docker Benchmark:** Control 4.9

## Why This Matters

Docker image layers are content-addressed and immutable. Every `RUN`, `COPY`, and `ENV` instruction creates a new layer, and all layers — including intermediate ones — are stored in the image manifest. Running `docker history --no-trunc <image>` or `docker inspect` reveals the full build-time arguments and environment variables from every layer. This means that `ENV DATABASE_PASSWORD=s3cr3t` will be visible to anyone who can pull the image, including read-only registry users, CI pipelines, and — critically — in the event of a registry breach.

This is not a theoretical risk: multiple public Docker Hub repositories have been found with embedded AWS keys, database passwords, and OAuth tokens visible in image history. The 2019 Docker Hub breach exposed approximately 190,000 accounts; any images in those repositories with credentials in layer history were fully compromised.

Even with `ARG` (which Docker does not expose in the final image environment by default), the value is still visible in `docker history` for the build layer where it was first set. An intermediate `RUN` step that uses the secret writes it to the layer filesystem if any echo or debug output is present, making it recoverable.

CAPEC-191 (Read Sensitive Constants Within an Executable) captures the inspection attack, and MITRE ATT&CK T1552.001 (Credentials in Files) covers the persistence of secrets in build artefacts.

## What Gets Flagged

The variable name must say it holds a credential (`PASSWORD`, `PASSWD`, `PASSPHRASE`, `SECRET`, `TOKEN`, `APIKEY`, `CREDENTIAL(S)`, `PRIVATEKEY`, a `PASS`/`PW`/`_PWD` word, or a name ending in `_KEY`). Reported: `ENV` with a literal value (in the `KEY=value` form, the legacy `KEY value` form, several pairs on one line and on continuation lines), `ENV` that copies a build arg into the image, and any credential-named `ARG`. The snippet is redacted.

```dockerfile
# FLAGGED
ENV POSTGRES_PASSWORD=Sup3rS3cret-prod
ENV DB_PASS hunter2-reporting
ENV APP_ENV=production \
    DATABASE_PASSWORD=pr0d-db-pa55
ARG NPM_TOKEN
ENV SENTRY_AUTH_TOKEN=${SENTRY_AUTH_TOKEN}
```

Not reported: names that point at or describe a secret (`*_FILE`, `*_PATH`, `*_URL`, `*_NAME`, `*_ID`, `*_TTL`, `*_ENABLED` and similar), public material (`GPG_KEY`, `PUBLIC_*`), lookalikes (`TOKENIZERS_PARALLELISM`, `KEYCLOAK_VERSION`), `ENV` values that are empty, booleans, short numbers, paths, plain URLs or placeholders, `RUN --mount=type=secret`, and text in comments, `RUN` commands or labels.

## Remediation

**Use Docker BuildKit's `--secret` mount for build-time secrets.** The `--secret` flag mounts a secret into a specific `RUN` step as a file at `/run/secrets/<id>`. The secret never appears in any image layer, in `docker history`, or in `docker inspect`.

```dockerfile
# SAFE: BuildKit secret mount — not stored in any layer
# syntax=docker/dockerfile:1
FROM alpine:3.20

RUN --mount=type=secret,id=api_key \
    API_KEY=$(cat /run/secrets/api_key) \
    && curl -H "Authorization: Bearer $API_KEY" https://api.example.com/setup \
    && unset API_KEY
```

Build with:

```bash
docker build --secret id=api_key,src=./api_key.txt .
```

**Pass secrets at runtime, not build time.** Declare the variable name without a value in the Dockerfile. The container orchestrator injects the actual value at container startup from a secrets store, never touching the image:

```dockerfile
# SAFE: variable name declared without any value — not baked into the image
FROM node:22.2.0-alpine3.20

# DATABASE_PASSWORD will be provided by the runtime environment
CMD ["node", "server.js"]
```

Inject at runtime via Kubernetes Secrets:

```yaml
env:
  - name: DATABASE_PASSWORD
    valueFrom:
      secretKeyRef:
        name: db-secret
        key: password
```

**Use a secrets manager at runtime.** Applications should fetch secrets from AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, or GCP Secret Manager at startup rather than reading from environment variables. This eliminates the secret from the container environment entirely.

**Scan images before pushing** to detect credentials in image history. Add a secrets-scanning step to your CI pipeline before the registry push:

```bash
# Scan image history for secrets with trufflehog
docker save myimage:latest | trufflehog docker --image=-
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CAPEC-191: Read Sensitive Constants Within an Executable](https://capec.mitre.org/data/definitions/191.html)
- [MITRE ATT&CK T1552.001 – Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [CIS Docker Benchmark v1.6 – Control 4.9: Ensure that COPY is used instead of ADD](https://www.cisecurity.org/benchmark/docker)
- [Docker documentation – Build secrets](https://docs.docker.com/build/building/secrets/)
- [Docker Reference – ARG instruction](https://docs.docker.com/reference/dockerfile/#arg)
- [Docker Reference – ENV instruction](https://docs.docker.com/reference/dockerfile/#env)
- [OWASP Docker Security Cheat Sheet – Do not store secrets in Dockerfiles](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [hadolint DL3012 – Provide an email address or URL for the maintainer](https://github.com/hadolint/hadolint/wiki/DL3012)
