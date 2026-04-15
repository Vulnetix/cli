---
title: "VNX-SEC-002 – Private Key Committed"
description: "Detects RSA, EC, DSA, and OpenSSH private keys committed to source code, which permanently expose cryptographic material even after deletion."
---

## Overview

This rule detects private key material embedded in any source file by matching PEM header markers: `BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN DSA PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`, and `BEGIN PRIVATE KEY`. Private keys are the secret half of asymmetric cryptography — whoever possesses them can impersonate services, decrypt TLS traffic, authenticate as the key owner, or sign arbitrary data. Once a private key appears in a git commit, it must be treated as permanently compromised, even if the file is deleted in a later commit.

**Severity:** Critical | **CWE:** [CWE-321 – Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html) | **OWASP ASVS v4:** V2.10.4, V6.4.1, V6.4.2

## Why This Matters

Git history is permanent and distributed. When a private key is pushed to a remote, every person or system that has cloned or fetched the repository holds a complete copy — including the commit containing the key. Deleting the file and pushing a new commit does not remove the key from the repository's object store; anyone running `git checkout <old-commit>` or `git show <sha>:<path>` can recover it instantly.

For TLS certificates, an exposed private key allows an attacker to perform man-in-the-middle attacks against your users. For SSH keys, it enables unauthorized access to every server where the public key is authorized. For code signing keys, it allows the attacker to sign malicious releases that appear legitimate. The impact is immediate and broad.

Private keys are never safe in source code — there is no "example" or "placeholder" key that is secure. Any PEM block in a repository is a finding that requires immediate action.

## What Gets Flagged

Any file containing a PEM-format private key block.

```
# FLAGGED: private key in a config or source file
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29O2bOHqh...
-----END RSA PRIVATE KEY-----
```

```python
# FLAGGED: key embedded as a string literal
PRIVATE_KEY = """
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
...
-----END OPENSSH PRIVATE KEY-----
"""
```

## Detecting a Compromise

Determine whether the key was used after it was exposed:

**SSH keys:** Check auth logs on all servers where the public key is authorized:
```bash
# On each server — look for logins using the compromised key
grep "Accepted publickey" /var/log/auth.log | grep "$(ssh-keygen -lf /path/to/public.key | awk '{print $2}')"

# GitHub/GitLab: check the web UI for recent SSH key usage
# GitHub: Settings → SSH and GPG keys → your key → "Last used"
```

**TLS certificates:** Check your web server access logs and Certificate Transparency logs for unexpected usage. Use `crt.sh` to audit issued certificates for your domains.

**Code signing keys:** Check your package registry for unexpected releases. For PyPI: `pip index versions <package>`. For npm: `npm view <package> time`.

## Remediation

1. **Revoke the key immediately — assume it is already compromised.** Do not wait.
   - **TLS/RSA keys:** Contact your certificate authority to revoke the certificate. For Let's Encrypt: `certbot revoke --cert-path /path/to/cert.pem`. Issue a new key pair and certificate.
   - **SSH keys:** Remove the public key from `~/.ssh/authorized_keys` on every server it is authorized on, and remove it from GitHub/GitLab SSH key settings.
   - **GPG keys:** Run `gpg --send-keys --keyserver keyserver.ubuntu.com <keyid>` after marking it as revoked with a revocation certificate.

2. **Generate a replacement key pair and store it properly.** Store private keys only in secrets managers, hardware security modules (HSMs), or encrypted vaults — never in files tracked by git.

3. **Remove the key from the current codebase.** Delete the file or string, commit, and push. Then proceed to step 4 — the key is still in history.

4. **Purge from git history.** Use `git-filter-repo` (preferred over `git filter-branch`) to rewrite history:

```bash
pip install git-filter-repo

# Remove a specific file entirely
git filter-repo --path path/to/key.pem --invert-paths

# Or replace the key content with a placeholder
git filter-repo --replace-text <(echo 'BEGIN RSA PRIVATE KEY==>REDACTED_PRIVATE_KEY')

# Force push the rewritten history (coordinate with your team first)
git push origin --force --all
git push origin --force --tags
```

5. **Verify no other secrets remain.** After rewriting history, run a full scan:

```bash
# gitleaks — comprehensive secrets scanning
gitleaks detect --source . --verbose --log-opts="--all"

# truffleHog — deep history scan
trufflehog git file://. --since-commit HEAD~100

# detect-secrets — scan and create baseline
pip install detect-secrets
detect-secrets scan --all-files . > .secrets.baseline
detect-secrets audit .secrets.baseline
```

6. **Load private keys from secure storage at runtime.** Use environment variables, AWS Secrets Manager, HashiCorp Vault, or Kubernetes secrets — not files in the repository.

```python
# SAFE: load private key from environment variable at runtime
import os
private_key_pem = os.environ['APP_PRIVATE_KEY']
```

```python
# SAFE: load private key from HashiCorp Vault
import hvac
client = hvac.Client(url='https://vault.example.com')
secret = client.secrets.kv.v2.read_secret_version(path='app/tls')
private_key_pem = secret['data']['data']['private_key']
```

7. **Add `.pem`, `.key`, and similar extensions to `.gitignore`** to prevent accidental future commits:

```bash
# .gitignore
*.pem
*.key
*.p12
*.pfx
id_rsa
id_ed25519
```

## References

- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [OWASP ASVS v4 – V6.4: Secret Management](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP: Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [git-filter-repo documentation](https://github.com/newren/git-filter-repo)
- [BFG Repo Cleaner](https://rtyley.github.io/bfg-repo-cleaner/)
- [Let's Encrypt – Revoking certificates](https://letsencrypt.org/docs/revoking/)
- [GitHub – Removing sensitive data](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [MITRE ATT&CK T1552.004 – Private Keys](https://attack.mitre.org/techniques/T1552/004/)
