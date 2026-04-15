---
title: "VNX-BASH-002 – curl or wget Output Piped Directly to Shell Interpreter"
description: "Detects shell scripts that pipe the output of curl or wget directly to bash, sh, zsh, ksh, or dash, executing remote code without any integrity verification and creating a supply-chain attack surface."
---

## Overview

This rule matches lines in Bash and shell scripts where `curl` or `wget` is followed by a pipe (`|`) leading to a shell interpreter (`bash`, `sh`, `zsh`, `ksh`, or `dash`). Both variants are covered: `curl <url> | bash` and `wget -O - <url> | bash`. Lines that are commented out are excluded.

This pattern downloads content from a remote URL and immediately executes it in the current shell session. There is no opportunity to inspect the script, verify its cryptographic signature, or check its hash against a known-good value. Any compromise of the remote server, CDN, DNS record, or network path (MITM) results in arbitrary command execution on the host running the script. This vulnerability maps to CWE-494 (Download of Code Without Integrity Check) and CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

**Severity:** High | **CWE:** [CWE-494 – Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html), [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

The `curl | bash` pattern is used extensively in software installation documentation and CI/CD setup scripts, which makes it feel normal — but normalisation does not eliminate the risk. In 2018, the `event-stream` npm package was compromised to steal Bitcoin wallets by an attacker who had been granted maintainer access. In 2021, the Codecov breach allowed attackers to modify a bash installer script (`bash <(curl -s https://codecov.io/bash)`) to exfiltrate environment variables — including CI secrets — from thousands of organisations including Twitch, HashiCorp, and Confluent.

The attack surface is broad: DNS hijacking, BGP hijacking, CDN compromise, TLS certificate mis-issuance, or a compromised maintainer account can all cause a different script to be served than expected. Even HTTPS does not protect against a compromised origin server. The only defence is to verify a cryptographic signature or hash of the downloaded script before executing it, in a separate step.

CAPEC-310 (Scanning for Vulnerable Software) and T1059.004 (Unix Shell) are relevant: attackers actively look for CI/CD pipelines that use this pattern as an initial access vector.

## What Gets Flagged

```bash
# FLAGGED: curl piped to bash — executes remote code immediately
curl -sSL https://get.example.com/install.sh | bash

# FLAGGED: wget variant piped to sh
wget -qO- https://install.example.com/setup.sh | sh

# FLAGGED: curl piped to zsh
curl https://raw.githubusercontent.com/example/tool/main/install.sh | zsh
```

## Remediation

1. **Download the script to a temporary file first.** This gives you the opportunity to inspect it and verify its integrity before executing.

2. **Verify a SHA-256 checksum or GPG signature** provided by the distributor on a separate channel (e.g., the project's GitHub release page or documentation) before executing the downloaded file.

3. **Use a package manager** (`apt`, `brew`, `nix`, `cargo install`, etc.) instead of curl-pipe-bash installers where possible. Package managers provide signed, reproducible installs.

```bash
# SAFE: download, verify checksum, then execute
SCRIPT_URL="https://get.example.com/install.sh"
EXPECTED_SHA256="abc123def456..."

curl -sSL "$SCRIPT_URL" -o /tmp/install.sh
echo "${EXPECTED_SHA256}  /tmp/install.sh" | sha256sum --check -

# Optionally inspect the script:
# less /tmp/install.sh

bash /tmp/install.sh
rm -f /tmp/install.sh
```

```bash
# SAFE: GPG-verified installer
curl -sSL https://example.com/install.sh -o /tmp/install.sh
curl -sSL https://example.com/install.sh.sig -o /tmp/install.sh.sig
gpg --verify /tmp/install.sh.sig /tmp/install.sh
bash /tmp/install.sh
```

## References

- [CWE-494: Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html)
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [Codecov Supply Chain Attack (2021)](https://about.codecov.io/security-update/)
- [OWASP – A08:2021 Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [ShellCheck – Use of curl pipe bash](https://www.shellcheck.net/)
- [MITRE ATT&CK T1059.004 – Unix Shell](https://attack.mitre.org/techniques/T1059/004/)
