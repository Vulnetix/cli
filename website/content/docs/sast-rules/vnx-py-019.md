---
title: "VNX-PY-019 – Paramiko Implicit Host Key Trust"
description: "Detect Python code that configures a paramiko SSHClient with AutoAddPolicy or WarningPolicy, silently accepting unverified SSH host keys and enabling man-in-the-middle attacks."
---

## Overview

This rule detects Python code that configures a `paramiko.SSHClient` with either `AutoAddPolicy` or `WarningPolicy` via `set_missing_host_key_policy()`. Both policies bypass the fundamental security mechanism of SSH host verification: they allow the client to connect to a server presenting an unknown or changed host key without raising an exception or requiring user confirmation. The difference is that `AutoAddPolicy` does so silently, while `WarningPolicy` logs a message but still proceeds with the connection.

SSH host key verification is the only mechanism that prevents a man-in-the-middle (MITM) attack against SSH. When a client connects, the server presents its public host key. If the client has previously recorded this key in a `known_hosts` file, it can verify that it is talking to the legitimate server. If the key is unknown or has changed (as would happen during a MITM attack), the client should refuse the connection. `AutoAddPolicy` and `WarningPolicy` both disable this protection.

The correct approach is to use `RejectPolicy` (which raises an exception for unknown host keys) combined with a pre-populated `known_hosts` file loaded via `client.load_system_host_keys()` or `client.load_host_keys()`. Alternatively, implement a custom `MissingHostKeyPolicy` subclass that validates a key fingerprint against a trusted allowlist.

**Severity:** High | **CWE:** [CWE-322 – Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)

## Why This Matters

A man-in-the-middle attack against SSH is not theoretical — it is a well-understood technique that any attacker on the network path between client and server can execute. In cloud deployments, container networking, and Kubernetes environments, the "network path" includes any compromised node, misconfigured network policy, or ARP/DNS poisoning attack. When `AutoAddPolicy` is in use, the attacker simply presents their own SSH host key; the client accepts it without complaint and begins sending credentials and data to the attacker's server.

The impact is severe: SSH is commonly used to run administrative commands, transfer files with sensitive content (private keys, configuration, database dumps), and execute deployment scripts. An MITM attacker intercepts all of this traffic in plaintext after the key exchange. They also receive any passwords or SSH agent forwarded keys used during the session.

Automated deployment systems and CI/CD pipelines are particularly at risk because they typically run with elevated privileges, connect to many hosts, and are not monitored for interactive anomalies the way human SSH sessions might be.

## What Gets Flagged

```python
import paramiko

# FLAGGED: AutoAddPolicy silently accepts any host key
def deploy_to_server(host: str, username: str, key_path: str) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, key_filename=key_path)
    stdin, stdout, stderr = client.exec_command("deploy.sh")

# FLAGGED: WarningPolicy logs a warning but still connects
def run_remote_command(host: str, cmd: str) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.WarningPolicy())
    client.connect(host)
    _, stdout, _ = client.exec_command(cmd)
    return stdout.read().decode()
```

The rule applies only to `.py` files.

## Remediation

1. Use `RejectPolicy` (or no explicit policy, as it is the default) and load a pre-populated `known_hosts` file.
2. In automated systems, populate the `known_hosts` file during provisioning (e.g., via `ssh-keyscan` at infrastructure setup time) and treat unexpected key changes as an error.
3. If the host key fingerprint is known ahead of time, implement a custom policy that validates it.

```python
import paramiko

# SAFE: RejectPolicy (default) + pre-loaded known_hosts
def deploy_to_server_safe(host: str, username: str, key_path: str) -> None:
    client = paramiko.SSHClient()
    # Load system known_hosts AND a project-specific file
    client.load_system_host_keys()
    client.load_host_keys("/etc/deploy/known_hosts")
    # RejectPolicy is the default, but being explicit is clearer
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(host, username=username, key_filename=key_path)
    stdin, stdout, stderr = client.exec_command("./deploy.sh")
    exit_status = stdout.channel.recv_exit_status()
    if exit_status != 0:
        raise RuntimeError(f"Deploy failed: {stderr.read().decode()}")

# SAFE: Custom policy that validates a known fingerprint
class FingerprintPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, expected_fingerprint: str) -> None:
        self.expected = expected_fingerprint

    def missing_host_key(self, client, hostname, key) -> None:
        import hashlib, base64
        fingerprint = base64.b64encode(
            hashlib.sha256(key.asbytes()).digest()
        ).decode()
        if fingerprint != self.expected:
            raise paramiko.SSHException(
                f"Host key fingerprint mismatch for {hostname}: "
                f"got {fingerprint}, expected {self.expected}"
            )

def connect_with_fingerprint(host: str, fingerprint: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(FingerprintPolicy(fingerprint))
    client.connect(host)
    return client
```

## References

- [CWE-322: Key Exchange without Entity Authentication](https://cwe.mitre.org/data/definitions/322.html)
- [Paramiko SSHClient Documentation](https://docs.paramiko.org/en/stable/api/client.html)
- [Paramiko MissingHostKeyPolicy](https://docs.paramiko.org/en/stable/api/client.html#paramiko.client.MissingHostKeyPolicy)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [OWASP Python Security Project](https://owasp.org/www-project-python-security/)
- [CAPEC-94: Man in the Middle Attack](https://capec.mitre.org/data/definitions/94.html)
- [MITRE ATT&CK T1557 – Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
