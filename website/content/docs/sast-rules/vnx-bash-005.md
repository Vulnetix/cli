---
title: "VNX-BASH-005 – Hardcoded Secret or Password in Shell Script"
description: "Reports a literal credential in a shell script or .env file: an assignment to a PASSWORD/SECRET/TOKEN/API_KEY-style name, a literal after a credential flag (--password, mysql -p, sshpass -p, curl -u), or a user:password pair in a connection URL. Placeholders, runtime references and single-word local defaults are not reported."
---

## Overview

This rule reports a literal credential written into a shell script (`.sh`, `.bash`, `.bats`, `.ksh`, `.zsh`, extensionless files with a shell shebang) or a `.env`/`.envrc` file: an assignment (`NAME=value`, `export`/`local`/`readonly`/`declare NAME=value`, quoted or bare) whose name ends in `PASSWORD`, `PASSWD`, `_PASS`, `SECRET`, `SECRET_KEY`, `TOKEN`, `API_KEY`, `APIKEY`, `PRIVATE_KEY` or `ACCESS_KEY` in any case; a literal passed to a credential flag (`--password`, `--token`, `--api-key`, `--client-secret`, `mysql -pVALUE`, `sshpass -p`, `curl -u user:VALUE`); and a `user:password@` pair inside a connection URL. The value is masked in the reported snippet. Not reported: values that reference a variable or command (`"$(cat /run/secrets/x)"`, `$GH_TOKEN`), empty values, placeholders (`changeme`, `your-...`, `<...>`, `xxxx`, `REPLACE_ME`, `dummy`), single-word local defaults shorter than 16 characters (`postgres`), paths, URLs and environment-variable names held in the variable, numbers and booleans, names that only contain a keyword (`PASSWORD_FILE`, `TOKEN_URL`, `MAX_TOKENS`), `--password-stdin`, comments, `echo` text, here-document bodies, test paths, and `.env.example`/`.sample` files.

Hardcoded credentials embedded directly in script files are visible to anyone with read access to the repository, build artifact, container image, or deployed filesystem. They cannot be rotated without a code change and a new deployment, and they appear in every copy of the codebase including forks, cached CI artefacts, and version control history. Even after the secret is removed from the file, it remains readable in `git log` unless the entire history is rewritten.

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Hardcoded secrets are one of the most consistently exploited vulnerability classes found in public repositories. Automated scanners constantly crawl GitHub for credential patterns, and a secret committed even briefly will typically be captured before it can be revoked. The 2022 CircleCI breach and numerous AWS key exposure incidents have shown that CI/CD environment scripts are a particularly high-value target.

In containerised environments, shell scripts are often baked into Docker images during build steps. A hardcoded `DB_PASSWORD` in an entrypoint script becomes readable by any process with access to the image layers — including untrusted build pipelines, image registry users, and anyone who runs `docker history`. This maps to ATT&CK technique T1552.001 (Credentials in Files) and CAPEC-191 (Read Sensitive Constants Within an Executable).

Beyond the immediate credential exposure, hardcoded secrets tend to be long-lived because rotating them requires coordinating a code change, a deployment, and updates to any environment that has a copy of the old value. This extended exposure window dramatically increases the blast radius of a compromise.

## What Gets Flagged

```bash
DB_PASSWORD="Pr0d-Backup!2024"                          # FLAGGED
export API_KEY='k3y-9f8a7b6c5d4e3f2a1b0c'               # FLAGGED
password=hunter2hunter                                  # FLAGGED: bare value
mysql -u root -pS3cureRootPw app < schema.sql           # FLAGGED
sshpass -p 'Deploy#Pass77' ssh deploy@web01 uptime      # FLAGGED
psql "postgresql://app:Sup3rS3cret@db.internal:5432/app"  # FLAGGED
```

Not flagged:

```bash
DB_PASSWORD="$(cat /run/secrets/db_password)"
API_KEY="${API_KEY:?API_KEY must be set}"
PASSWORD_FILE="/run/secrets/db_password"
echo "$TOKEN" | docker login -u ci --password-stdin registry.example.com
export PGPASSWORD=postgres        # single-word local default
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
