---
title: "VNX-BASH-005 – Hardcoded Secret or Password in Shell Script"
description: "Detects shell variable assignments where the variable name indicates a secret, password, token, or API key and the value is a non-empty string literal rather than a runtime reference."
---

## Overview

This rule scans Bash scripts (`.sh`, `.bash`) and environment files (`.env`) for variable assignments where the variable name matches common credential patterns — `PASSWORD`, `PASSWD`, `SECRET`, `TOKEN`, `API_KEY`, `APIKEY`, `PRIVATE_KEY`, `AUTH_TOKEN`, `ACCESS_KEY`, `DB_PASS`, and similar — and the assigned value is a quoted string literal of four or more characters. Lines that are commented out or that use variable expansion (`${...}`) as the value are excluded, since those patterns indicate a legitimate runtime reference.

Hardcoded credentials embedded directly in script files are visible to anyone with read access to the repository, build artifact, container image, or deployed filesystem. They cannot be rotated without a code change and a new deployment, and they appear in every copy of the codebase including forks, cached CI artefacts, and version control history. Even after the secret is removed from the file, it remains readable in `git log` unless the entire history is rewritten.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded secrets are one of the most consistently exploited vulnerability classes found in public repositories. Automated scanners constantly crawl GitHub for credential patterns, and a secret committed even briefly will typically be captured before it can be revoked. The 2022 CircleCI breach and numerous AWS key exposure incidents have shown that CI/CD environment scripts are a particularly high-value target.

In containerised environments, shell scripts are often baked into Docker images during build steps. A hardcoded `DB_PASSWORD` in an entrypoint script becomes readable by any process with access to the image layers — including untrusted build pipelines, image registry users, and anyone who runs `docker history`. This maps to ATT&CK technique T1552.001 (Credentials in Files) and CAPEC-191 (Read Sensitive Constants Within an Executable).

Beyond the immediate credential exposure, hardcoded secrets tend to be long-lived because rotating them requires coordinating a code change, a deployment, and updates to any environment that has a copy of the old value. This extended exposure window dramatically increases the blast radius of a compromise.

## What Gets Flagged

```bash
# FLAGGED: plaintext password assigned to PASSWORD variable
PASSWORD='supersecret123'

# FLAGGED: API key hardcoded in script
API_KEY="sk-prod-abcdef1234567890abcdef"

# FLAGGED: token embedded in .env file
AUTH_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.real"

# FLAGGED: database password hardcoded
DB_PASSWORD="Passw0rd!"
```

## Remediation

1. Remove the hardcoded value immediately and rotate the credential — assume it has been compromised if it was ever committed.
2. Inject secrets at runtime via environment variables provided by your CI/CD system, container orchestrator, or a secrets manager.
3. Use a vault product (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, GitHub Actions Secrets) and retrieve the value at startup.
4. Add a pre-commit hook (e.g., `detect-secrets`, `gitleaks`) to your repository to prevent future accidental commits.

```bash
# SAFE: read password from environment variable injected at runtime
PASSWORD="${PASSWORD:?DB_PASSWORD environment variable must be set}"

# SAFE: retrieve from a secrets manager CLI at startup
API_KEY=$(aws secretsmanager get-secret-value \
    --secret-id prod/myapp/api_key \
    --query SecretString \
    --output text)

# SAFE: Docker/Kubernetes secrets mounted as files
DB_PASSWORD=$(cat /run/secrets/db_password)
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [OWASP – Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitHub Docs – Encrypted Secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
- [MITRE ATT&CK T1552.001 – Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
