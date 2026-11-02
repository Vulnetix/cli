---
title: "VNX-BASH-002 – Downloaded Script Executed Without an Integrity Check"
description: "Reports a shell script that runs code it has just downloaded with curl or wget without verifying it: piped into an interpreter (directly or through filters such as base64 -d), passed to one as a command or process substitution, or saved and run with no checksum or signature check in between."
---

## Overview

This rule reports a shell script that runs code it has just downloaded with `curl` or `wget` without verifying it: the download piped into an interpreter (`| bash`, `| sudo -E bash -s --`, `| VAR=x sh -`, `| /bin/sh`, `| python3 -`, `| perl`, `| ruby`, `| node`, `| php`), including a pipeline continued over several lines; passed to one as a command or process substitution (`bash -c "$(curl ...)"`, `bash <(curl ...)`, `source <(wget -qO- ...)`); or saved to a file that the next lines run with no `sha256sum`/`shasum`/`gpg`/`cosign`/`minisign`/`openssl dgst` check in between. Not reported: a download piped to a non-interpreter (`tar`, `jq`, `gpg --dearmor`, `sha256sum`, `tee`), a verified download, a binary or archive that is downloaded but not run here, local files piped to a shell, and the command inside a string, `echo`, comment or usage here-document. Dockerfile `RUN` lines and CI workflow files are not covered by this rule.

This pattern downloads content from a remote URL and immediately executes it in the current shell session. There is no opportunity to inspect the script, verify its cryptographic signature, or check its hash against a known-good value. Any compromise of the remote server, CDN, DNS record, or network path (MITM) results in arbitrary command execution on the host running the script. This vulnerability maps to CWE-494 (Download of Code Without Integrity Check) and CWE-829 (Inclusion of Functionality from Untrusted Control Sphere).

**Severity:** High | **CWE:** [CWE-494 – Download of Code Without Integrity Check](https://cwe.mitre.org/data/definitions/494.html), [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

The `curl | bash` pattern is used extensively in software installation documentation and CI/CD setup scripts, which makes it feel normal — but normalisation does not eliminate the risk. In 2018, the `event-stream` npm package was compromised to steal Bitcoin wallets by an attacker who had been granted maintainer access. In 2021, the Codecov breach allowed attackers to modify a bash installer script (`bash <(curl -s https://codecov.io/bash)`) to exfiltrate environment variables — including CI secrets — from thousands of organisations including Twitch, HashiCorp, and Confluent.

The attack surface is broad: DNS hijacking, BGP hijacking, CDN compromise, TLS certificate mis-issuance, or a compromised maintainer account can all cause a different script to be served than expected. Even HTTPS does not protect against a compromised origin server. The only defence is to verify a cryptographic signature or hash of the downloaded script before executing it, in a separate step.

CAPEC-310 (Scanning for Vulnerable Software) and T1059.004 (Unix Shell) are relevant: attackers actively look for CI/CD pipelines that use this pattern as an initial access vector.

## What Gets Flagged

```bash
curl -fsSL https://get.example.com/install.sh | bash                    # FLAGGED
curl -sSL https://sh.example.dev | sudo -E bash -s -- --channel stable  # FLAGGED
wget -qO- https://install.example.net/agent.sh | /bin/bash              # FLAGGED
bash <(curl -fsSL https://get.example.com/install.sh)                   # FLAGGED
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/example/setup/main/install.sh)"  # FLAGGED
curl -s https://example.org/payload | base64 -d | sh                    # FLAGGED
curl -fsSL https://example.org/install.sh > /tmp/install.sh
bash /tmp/install.sh --yes                                              # FLAGGED: run unverified
```

Not flagged:

```bash
curl -fsSL https://example.com/tool.tar.gz | tar -xz
curl -fsSLo install.sh https://example.com/install.sh
echo "${EXPECTED_SHA256}  install.sh" | sha256sum -c - && bash install.sh
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
