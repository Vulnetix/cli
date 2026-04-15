---
title: "VNX-GO-001 – Missing go.sum"
description: "Detect Go projects that are missing a go.sum lockfile, leaving them vulnerable to software supply chain attacks via tampered or substituted modules."
---

## Overview

This rule flags Go projects that have a `go.mod` file but no corresponding `go.sum` file. The `go.sum` file records the expected cryptographic checksums of every module your project depends on. Without it, Go has no way to verify that the module code it downloads at build time matches what you originally tested against, opening a direct path for supply chain compromise. This maps to [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html).

**Severity:** High | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

## Why This Matters

Without a `go.sum`, a compromised module proxy, a DNS hijack, or a typosquat package can silently substitute malicious code into your build. The attacker does not need access to your repository — they only need to interfere with the module download path between your build environment and the module origin. In CI/CD pipelines this risk is elevated because builds frequently download fresh dependencies from the internet. A single poisoned module can exfiltrate secrets, establish persistence, or tamper with application logic before your code even starts. MITRE ATT&CK technique T1195.001 (Supply Chain Compromise: Compromise Software Dependencies) describes exactly this attack class.

## What Gets Flagged

The rule fires when a directory contains Go source files (registered as a Go project directory) but the file `go.sum` is absent from that same directory. This typically means the project was initialized with `go mod init` but `go mod tidy` was never run, or `go.sum` was deliberately excluded from version control via `.gitignore`.

```go
// FLAGGED: project directory has go.mod but no go.sum
// $ ls
// go.mod   main.go
// (go.sum is missing)
```

## Remediation

1. **Generate the lockfile.** Run `go mod tidy` in the directory containing `go.mod`. This downloads all dependencies, resolves the full dependency graph, and writes both `go.sum` and an updated `go.mod`.

```bash
go mod tidy
```

2. **Commit `go.sum` to version control.** The file must be present in source control so every build — locally and in CI — uses the same verified checksums.

```bash
git add go.sum
git commit -m "chore: add go.sum lockfile"
```

3. **Verify integrity before building.** In CI pipelines, add a verification step to confirm no dependency has been tampered with since the last commit:

```bash
go mod verify
```

4. **Prevent accidental exclusion.** Check that `go.sum` is not listed in `.gitignore`. If it is, remove that line.

5. **Use `GONOSUMCHECK` with caution.** The `GONOSUMCHECK` environment variable bypasses checksum verification for matched module paths. Only use it for internal modules hosted on private infrastructure that is not accessible to the Go checksum database, and never set it globally in CI.

```bash
# SAFE: verify module checksums before any build step
go mod verify && go build ./...
```

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP Software Component Verification Standard](https://owasp.org/www-project-software-component-verification-standard/)
- [Go Modules Reference – go.sum files](https://go.dev/ref/mod#go-sum-files)
- [Go Modules Reference – go mod verify](https://go.dev/ref/mod#go-mod-verify)
- [MITRE ATT&CK T1195.001 – Supply Chain Compromise: Compromise Software Dependencies](https://attack.mitre.org/techniques/T1195/001/)
- [CAPEC-185: Malicious Software Download](https://capec.mitre.org/data/definitions/185.html)
