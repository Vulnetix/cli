---
title: "VNX-SEC-016 – TLS Verification Disabled in Shell Command"
description: "Detects curl -k/--insecure and wget --no-check-certificate in shell scripts and commands, which disable TLS certificate validation and enable man-in-the-middle attacks."
---

## Overview

This rule detects the use of `curl -k`, `curl --insecure`, and `wget --no-check-certificate` in shell scripts and command strings in source files. These flags instruct the HTTP client to skip TLS certificate validation entirely, meaning connections are made without verifying that the server's certificate is issued by a trusted CA, valid for the target hostname, or not expired. This disables one of the fundamental security guarantees of TLS — that you are communicating with the intended server and not an impersonator.

**Severity:** Medium | **CWE:** [CWE-295 – Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

## Why This Matters

In CI/CD pipelines and build scripts, `curl -k` is commonly added as a "quick fix" when a certificate validation error occurs — perhaps the internal service uses a self-signed certificate, or the CA bundle in the container is outdated. The developer gets the pipeline to pass, but the fix introduces a persistent vulnerability.

An attacker who can intercept network traffic between the build agent and the target server (for example, by compromising a shared CI runner, performing an ARP spoof on the build network, or operating a malicious exit node) can serve a fraudulent response. If the script is downloading a binary, configuration file, or script and executing it, the attacker can substitute malicious content. This is a supply chain attack vector that has been used in real targeted attacks against software build infrastructure.

Even in "trusted" internal networks, TLS verification provides defence-in-depth against lateral movement by an already-compromised host.

## What Gets Flagged

```bash
# FLAGGED: curl with TLS verification disabled
curl -k https://internal-api.example.com/config.json -o config.json
curl --insecure -L https://releases.example.com/latest/binary -o binary
```

```bash
# FLAGGED: wget with certificate check disabled
wget --no-check-certificate https://internal.example.com/install.sh | bash
```

```python
# FLAGGED: subprocess calling curl with -k
import subprocess
subprocess.run(["curl", "-k", "-o", "data.json", "https://api.example.com"])
```

## Remediation

1. **Remove the `-k`/`--insecure`/`--no-check-certificate` flag** and fix the underlying certificate issue properly.

2. **For internal services with self-signed certificates**, provide the CA certificate explicitly instead of disabling validation entirely:

```bash
# SAFE: provide the custom CA certificate
curl --cacert /etc/ssl/certs/internal-ca.crt https://internal-api.example.com/config.json

# Or set the CA bundle path
export CURL_CA_BUNDLE=/etc/ssl/certs/internal-ca.crt
curl https://internal-api.example.com/config.json
```

```bash
# SAFE: wget with custom CA
wget --ca-certificate=/etc/ssl/certs/internal-ca.crt https://internal.example.com/install.sh
```

3. **Update the CA bundle in your Docker image or build environment** if the issue is an outdated bundle:

```dockerfile
# In your Dockerfile
RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates
# Or for Alpine
RUN apk add --no-cache ca-certificates
```

4. **Obtain a properly signed certificate** for internal services. Let's Encrypt is free for public-facing services. For internal services, consider a private CA managed by tools like `step-ca` (Smallstep) or `cfssl`, and distribute the CA certificate to your build agents via configuration management.

5. **In CI/CD pipelines**, mount the CA certificate as a secret or build artifact rather than disabling TLS:

```yaml
# SAFE: GitHub Actions — add custom CA certificate
- name: Add internal CA certificate
  run: |
    echo "${{ secrets.INTERNAL_CA_CERT }}" | sudo tee /usr/local/share/ca-certificates/internal-ca.crt
    sudo update-ca-certificates
```

6. **For certificate pinning in high-security contexts**, use `--pinnedpubkey`:

```bash
# SAFE: pin the server's public key hash
curl --pinnedpubkey "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" \
     https://api.example.com
```

## References

- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)
- [OWASP: Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [curl: --cacert documentation](https://curl.se/docs/manpage.html#--cacert)
- [Smallstep step-ca: Private CA](https://smallstep.com/docs/step-ca/)
- [MITRE ATT&CK T1557 – Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)
- [CAPEC-94: Adversary in the Middle (AiTM)](https://capec.mitre.org/data/definitions/94.html)
