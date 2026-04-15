---
title: "VNX-DOCKER-007 – Dockerfile Missing HEALTHCHECK Instruction"
description: "Detects runtime Dockerfiles that define a CMD or ENTRYPOINT but omit a HEALTHCHECK instruction, preventing container orchestrators from detecting unhealthy application states."
---

## Overview

This rule flags Dockerfiles that contain a `CMD` or `ENTRYPOINT` instruction (indicating they produce a runtime image, not just a build stage) but do not include any `HEALTHCHECK` instruction. Without a health check, the container runtime and orchestrators such as Kubernetes, Docker Swarm, and ECS can only observe whether the container process is alive — they cannot detect when the application inside is deadlocked, out of memory, wedged on a database connection, or serving errors. This maps to CWE-754 (Improper Check for Unusual or Exceptional Conditions).

A container that is running but unhealthy continues to receive traffic from load balancers and service discovery, silently degrading the experience for users while appearing healthy to monitoring systems that only check container status. The `HEALTHCHECK` instruction allows Docker and orchestrators to probe the application directly and mark the container as unhealthy, triggering automated restarts and replacement.

The rule only fires on images that have a `CMD` or `ENTRYPOINT` — builder stages, scratch-based stages, and base images without an entrypoint are not flagged, as adding a health check to them is either not meaningful or not possible.

**Severity:** Low | **CWE:** [CWE-754 – Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)

## Why This Matters

In production container environments, the container lifecycle is managed by an orchestrator rather than a human operator. When an application enters a degraded state — such as a Go process that is stuck waiting on a locked mutex, a Node.js event loop that is blocked, or a web server that has exhausted its thread pool — the orchestrator has no way to know this has happened unless the container itself reports its health.

Without a `HEALTHCHECK`, rolling deployments may complete successfully while the new containers are actually in a broken state, since the orchestrator sees the process as running and marks the rollout as healthy. A correctly configured health check ensures that the orchestrator waits for actual application readiness before marking a deployment complete and before routing live traffic to the new container.

This also matters for security incident response: a compromised container that has been forced into a crash loop or degraded state is more likely to be detected and replaced if health checks are in place, reducing the window of exposure.

## What Gets Flagged

```dockerfile
# FLAGGED: CMD present but no HEALTHCHECK instruction in the file
FROM node:20-slim
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
CMD ["node", "server.js"]
```

```dockerfile
# FLAGGED: ENTRYPOINT defined, no HEALTHCHECK
FROM golang:1.22-alpine AS build
RUN go build -o /app .

FROM alpine:3.19
COPY --from=build /app /app
ENTRYPOINT ["/app"]
```

## Remediation

1. **Add a `HEALTHCHECK` instruction that probes the application's HTTP readiness endpoint** using `curl` or `wget`. Tune the interval, timeout, start period, and retries to match your application's startup time and expected response latency.

   ```dockerfile
   # SAFE: HTTP health check for a web server
   FROM node:20-slim
   WORKDIR /app
   COPY . .
   RUN npm ci --omit=dev
   HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
       CMD curl -f http://localhost:3000/healthz || exit 1
   CMD ["node", "server.js"]
   ```

2. **For non-HTTP services, use a process-level or port-level check** with `nc` (netcat) or a custom health binary bundled in the image.

   ```dockerfile
   # SAFE: TCP port check for a non-HTTP service
   FROM alpine:3.19
   COPY myservice /usr/local/bin/myservice
   HEALTHCHECK --interval=15s --timeout=3s \
       CMD nc -z localhost 8080 || exit 1
   ENTRYPOINT ["/usr/local/bin/myservice"]
   ```

3. **For distroless or scratch images**, embed a dedicated health check binary in the image and use it as the `HEALTHCHECK CMD`.

   ```dockerfile
   # SAFE: distroless image with embedded health check binary
   FROM gcr.io/distroless/static-debian12
   COPY myapp /myapp
   COPY healthcheck /healthcheck
   HEALTHCHECK --interval=30s CMD ["/healthcheck"]
   ENTRYPOINT ["/myapp"]
   ```

## References

- [CWE-754: Improper Check for Unusual or Exceptional Conditions](https://cwe.mitre.org/data/definitions/754.html)
- [Docker documentation – HEALTHCHECK instruction](https://docs.docker.com/reference/dockerfile/#healthcheck)
- [Docker best practices – Health checks](https://docs.docker.com/build/building/best-practices/)
- [CIS Docker Benchmark v1.6 – 4.6 Add HEALTHCHECK instruction to the container image](https://www.cisecurity.org/benchmark/docker)
- [hadolint DL3011 – HEALTHCHECK is missing](https://github.com/hadolint/hadolint/wiki/DL3011)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
