---
title: "VNX-DOCKER-001 – Dockerfile Missing USER Directive"
description: "Detects Dockerfiles that do not include a USER directive, causing containers to run as root and significantly expanding the blast radius of any container compromise."
---

## Overview

This rule detects Dockerfiles that contain a `FROM` instruction but no `USER` directive. Without an explicit `USER` instruction, Docker containers start and run all processes as `root` (UID 0) by default. Running as root inside a container means that any process compromise, command injection, or path traversal vulnerability in the containerised application can interact with the host system — including mounted volumes, the container socket, and other containers on shared networks — with elevated privileges. This maps to CWE-250 (Execution with Unnecessary Privileges).

**Default behaviour:** Running as root IS the Docker default. You must explicitly opt out by adding a `USER` instruction.

**Severity:** Medium | **CWE:** [CWE-250 – Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html) | **CIS Docker Benchmark:** Control 4.1

## Why This Matters

Container isolation is not a security boundary equivalent to a virtual machine. If a container runs as root and an attacker achieves code execution inside it, they can potentially escape to the host or move laterally through the cluster. Multiple published container escape CVEs have been substantially more impactful because the target container process was running as root:

- **CVE-2019-5736** (runc overwrite): Exploiting a file descriptor leak in runc, an attacker in a root container could overwrite the host runc binary and gain root on the host. Non-root containers had no write access to the binary.
- **CVE-2024-21626** (runc working directory escape): A `WORKDIR` escape in runc allowed a root container process to reach the host filesystem through `/proc/self/fd`. A non-root process had reduced access to host paths even when the escape technique succeeded.
- **CVE-2022-0811** (CRI-O core dump path injection): A root container could exploit a sysctl injection to gain host code execution via a crafted core dump path. Non-root containers were not affected by this specific vector.

In Kubernetes environments, a root container combined with a `hostPath` volume mount or a container socket mount is sufficient to compromise the entire node. CIS Docker Benchmark control 4.1 explicitly states "Ensure that a user for the container has been created" and is one of the most commonly failed controls in production container audits. MITRE ATT&CK T1611 (Escape to Host) documents the escalation pathway.

The principle of least privilege applies inside containers just as it does on bare metal: your application almost certainly does not need root to serve HTTP requests, process jobs, or run a database — and running as a non-root user limits what an attacker can do if they compromise the process.

## What Gets Flagged

The rule checks every file with a `.dockerfile` extension or named `Dockerfile`. If the file contains a `FROM` instruction but no `USER` instruction (checked case-insensitively with a regex), a finding is raised for the whole file.

```dockerfile
# FLAGGED: no USER directive — container runs as root by default
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y python3

COPY app.py /app/app.py

CMD ["python3", "/app/app.py"]
```

## Remediation

**Create a dedicated non-root user and switch to it with `USER` before the entrypoint.** Use a numeric UID (e.g., `1001`) rather than a named user where possible — numeric UIDs work without `/etc/passwd` entries in distroless images and are required by some Kubernetes admission controllers.

```dockerfile
# SAFE: non-root user created and activated
FROM ubuntu:22.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --no-create-home --shell /bin/false appuser

COPY --chown=appuser:appgroup app.py /app/app.py

USER 1001

CMD ["python3", "/app/app.py"]
```

Use `COPY --chown=<user>:<group>` to set correct file ownership at copy time rather than adding a separate `chmod` layer. Files copied before the `USER` instruction are owned by root; files copied after inherit the active user, but explicit `--chown` is clearer and works regardless of instruction order.

For distroless or minimal images, the base image may already run as a non-root user:

```dockerfile
# SAFE: distroless image with built-in non-root default (uid 65532 "nonroot")
FROM gcr.io/distroless/python3-debian12

COPY app.py /app/app.py

CMD ["/app/app.py"]
```

Enforce the requirement in Kubernetes as a defence-in-depth measure to reject root containers even if the Dockerfile is misconfigured:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1001
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault
```

## References

- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [CAPEC-69: Target Programs with Elevated Privileges](https://capec.mitre.org/data/definitions/69.html)
- [MITRE ATT&CK T1611 – Escape to Host](https://attack.mitre.org/techniques/T1611/)
- [CIS Docker Benchmark v1.6 – Control 4.1: Ensure a user for the container has been created](https://www.cisecurity.org/benchmark/docker)
- [Docker Reference – USER instruction](https://docs.docker.com/reference/dockerfile/#user)
- [Docker Build Best Practices – User](https://docs.docker.com/build/building/best-practices/#user)
- [OWASP Docker Security Cheat Sheet – Rule 2: Set a user](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CVE-2019-5736 – runc container escape](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)
- [CVE-2024-21626 – runc working directory escape](https://nvd.nist.gov/vuln/detail/CVE-2024-21626)
- [hadolint DL3002 – Last USER should not be root](https://github.com/hadolint/hadolint/wiki/DL3002)
