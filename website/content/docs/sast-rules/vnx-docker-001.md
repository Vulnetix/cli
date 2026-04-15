---
title: "VNX-DOCKER-001 – Dockerfile Missing USER Directive"
description: "Detects Dockerfiles that do not include a USER directive, causing containers to run as root and significantly expanding the blast radius of any container compromise."
---

## Overview

This rule detects Dockerfiles that contain a `FROM` instruction but no `USER` directive. Without an explicit `USER` instruction, Docker containers start and run all processes as `root` (UID 0) by default. Running as root inside a container means that any process compromise, command injection, or path traversal vulnerability in the containerized application can interact with the host system — including mounted volumes, the container socket, and other containers on shared networks — with elevated privileges. This maps to CWE-250 (Execution with Unnecessary Privileges).

**Severity:** Medium | **CWE:** [CWE-250 – Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

## Why This Matters

Container isolation is not a security boundary equivalent to a VM. If a container runs as root and an attacker achieves code execution inside it, they can potentially escape to the host or move laterally through the cluster. Common container escape techniques — runc CVE-2019-5736, runc CVE-2024-21626, and Kubernetes CVE-2022-0811 — all became substantially more impactful because the container process was running as root.

In Kubernetes environments, a root container combined with a hostPath volume mount or a container socket mount is sufficient to compromise the entire node. CIS Docker Benchmark control 4.1 explicitly states "Ensure that a user for the container has been created" and is one of the most commonly failed controls in production container audits. MITRE ATT&CK T1611 (Escape to Host) documents the escalation pathway.

The principle of least privilege applies inside containers just as it does on bare metal: your application almost certainly does not need root to serve HTTP requests, process jobs, or run a database — and running as a non-root user limits what an attacker can do if they compromise the process.

## What Gets Flagged

The rule checks every file with a `.dockerfile` extension or named `Dockerfile`. If the file contains a `FROM` instruction but no `USER` instruction (checked case-insensitively with a regex), a finding is raised for the whole file.

```dockerfile
# FLAGGED: no USER directive — container runs as root
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y python3

COPY app.py /app/app.py

CMD ["python3", "/app/app.py"]
```

## Remediation

1. **Create a dedicated non-root user in the Dockerfile and switch to it with `USER`.** Use a numeric UID (e.g., `1001`) rather than a named user when possible, as numeric UIDs work without `/etc/passwd` entries in distroless images and are required by some Kubernetes admission controllers.

   ```dockerfile
   # SAFE: non-root user created and activated
   FROM ubuntu:22.04

   RUN apt-get update && apt-get install -y python3 \
       && groupadd --gid 1001 appgroup \
       && useradd --uid 1001 --gid appgroup --shell /bin/false appuser

   COPY --chown=appuser:appgroup app.py /app/app.py

   USER 1001

   CMD ["python3", "/app/app.py"]
   ```

2. **Use `--chown` with `COPY` and `ADD` to set correct file ownership.** Files copied before the `USER` instruction are owned by root. Use `COPY --chown=<user>:<group>` to ensure the application user can read them.

3. **Use distroless or minimal base images.** Images like `gcr.io/distroless/python3` run as a non-root user by default and have no shell, dramatically reducing the attack surface.

   ```dockerfile
   # SAFE: distroless image with built-in non-root default
   FROM gcr.io/distroless/python3-debian12

   COPY app.py /app/app.py

   CMD ["/app/app.py"]
   ```

4. **Verify with `docker run --user` that the application works as a non-root user** before deploying. Some applications write to root-owned directories at startup; these must be fixed rather than worked around by granting root.

5. **Enforce in Kubernetes with a PodSecurityPolicy or SecurityContext.** Add `runAsNonRoot: true` and `runAsUser: 1001` to your Kubernetes `securityContext` as a defense-in-depth measure to prevent root containers from running even if the Dockerfile is misconfigured.

## References

- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [CAPEC-69: Target Programs with Elevated Privileges](https://capec.mitre.org/data/definitions/69.html)
- [MITRE ATT&CK T1611 – Escape to Host](https://attack.mitre.org/techniques/T1611/)
- [CIS Docker Benchmark v1.6 – Control 4.1](https://www.cisecurity.org/benchmark/docker)
- [Docker Security Best Practices – Non-root users](https://docs.docker.com/develop/security-best-practices/)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [runc CVE-2019-5736 – Container escape requiring root](https://nvd.nist.gov/vuln/detail/CVE-2019-5736)
