---
title: "VNX-DOCKER-005 – Dockerfile Privileged Container Flag"
description: "Detects --privileged mode in Dockerfiles and docker-compose files, which disables all container security boundaries and grants full access to the host kernel."
---

## Overview

This rule detects the `--privileged` flag in Dockerfile `RUN`, `CMD`, or `ENTRYPOINT` instructions and the `privileged: true` key in `docker-compose.yml` or `docker-compose.yaml` files. Running a container in privileged mode disables every security mechanism that container runtimes apply by default: seccomp profiles, AppArmor/SELinux policies, capability restrictions, and device isolation are all removed. The container process gains access to the host kernel as if it were running directly on the machine. This maps to CWE-250 (Execution with Unnecessary Privileges).

When `--privileged` appears in a Dockerfile instruction, it means the image itself is designed to run in elevated mode and any operator deploying it may inherit that expectation without understanding the risk. When it appears in a Compose file, it typically means the developer has opted in for debugging convenience and left the configuration in place for production.

Running privileged containers is one of the most reliable container escape primitives available to attackers. Multiple public exploits and CTF challenges demonstrate that a process inside a privileged container can mount the host filesystem, load kernel modules, and gain root on the host within seconds.

**Severity:** Critical | **CWE:** [CWE-250 – Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

## Why This Matters

A privileged container shares the host's Linux capability set in full. An attacker who achieves code execution inside such a container — through a dependency vulnerability, a deserialization bug, or a misconfigured application — can immediately pivot to the host by mounting `/dev/sda`, injecting into the host cgroup namespace, or loading a kernel module that grants persistent access.

CAPEC-122 (Privilege Abuse) and MITRE ATT&CK T1611 (Escape to Host) document this attack pattern. Real-world incidents including the 2019 `runc` CVE-2019-5736 demonstrated that even non-privileged containers can be dangerous, but privileged containers remove the last line of defence entirely.

The principle of least privilege requires that containers be granted only the specific Linux capabilities they need. If a container requires access to a specific device or system call, the correct approach is to grant that individual capability with `--cap-add` or the Compose `cap_add` key, rather than removing all restrictions wholesale.

## What Gets Flagged

```dockerfile
# FLAGGED: --privileged disables all security boundaries
RUN --privileged ./setup-network.sh

# FLAGGED: entrypoint that requests privileged mode
ENTRYPOINT ["docker-entrypoint.sh", "--privileged"]
```

```yaml
# FLAGGED: docker-compose.yml granting privileged mode to a service
services:
  app:
    image: myapp:latest
    privileged: true
```

## Remediation

1. **Remove `--privileged` and identify which specific capability the code actually requires.** Common substitutions are `--cap-add NET_ADMIN` for network configuration, `--cap-add SYS_PTRACE` for debugging, and `--cap-add SYS_ADMIN` for limited system administration (use this sparingly).

   ```dockerfile
   # SAFE: grant only the network administration capability needed
   FROM debian:12-slim
   RUN apt-get install -y iproute2

   # At runtime, pass --cap-add NET_ADMIN rather than --privileged
   ```

2. **In Compose files, replace `privileged: true` with a `cap_add` list** scoped to the minimum required capabilities. Drop all others explicitly with `cap_drop: [ALL]`.

   ```yaml
   # SAFE: minimal capability grant instead of full privilege
   services:
     app:
       image: myapp:latest
       cap_drop:
         - ALL
       cap_add:
         - NET_ADMIN
   ```

3. **For device access, use `devices` mapping** rather than `--privileged` to expose only the specific device node the container requires.

   ```yaml
   # SAFE: expose only a specific device
   services:
     scanner:
       image: scanner:latest
       devices:
         - /dev/video0:/dev/video0
   ```

## References

- [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)
- [CAPEC-122: Privilege Abuse](https://capec.mitre.org/data/definitions/122.html)
- [MITRE ATT&CK T1611 – Escape to Host](https://attack.mitre.org/techniques/T1611/)
- [Docker documentation – Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [CIS Docker Benchmark v1.6 – 5.4 Do not use privileged containers](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [hadolint DL3002 – Avoid privileged containers](https://github.com/hadolint/hadolint/wiki/DL3002)
