---
title: "VNX-SEC-032 – PGP Private Key Block Hardcoded"
description: "Detect PGP/GPG private key blocks committed to source code, which permanently expose the private key in git history and require immediate revocation and replacement."
---

## Overview

This rule flags any file containing the PGP armored private key header `-----BEGIN PGP PRIVATE KEY BLOCK-----`. This string marks the beginning of an exported PGP or GPG private key in ASCII armor format. A private key present in source code is exposed to everyone who can read the repository and, critically, persists in git history permanently even if the file is subsequently modified or deleted — the key is accessible in every historical commit that contained it.

PGP private keys are used to sign data (including software releases, git commits, and email), decrypt messages encrypted to the associated public key, and authenticate in systems that trust the key. Exposure of a private key allows an attacker to create counterfeit signatures that appear to come from the key's owner, decrypt any message ever encrypted to this key (including historical messages), and impersonate the key owner in any system that trusts the key.

This rule corresponds to [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html).

**Severity:** Critical | **CWE:** [CWE-321 – Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)

## Why This Matters

PGP private keys are among the most sensitive credentials that can be committed to a repository. Unlike an API token that can be revoked by a single API call, the consequences of a PGP private key leak extend to the past as well as the future. Every document, email, or software release ever signed with this key can now be forged retroactively. Every message encrypted to this key's public key can be decrypted.

In software development contexts, PGP keys are commonly used to sign release artifacts, sign git tags and commits (which enables "verified commits" in GitHub), and sign package manifests for package registries. If the signing key for a software project is compromised, an attacker can release counterfeit versions of the software with valid cryptographic signatures, potentially distributing malware to users who verify signatures as a trust mechanism.

The git history problem makes this particularly severe: rewriting history to remove the key requires a force-push to all branches, invalidation of all open pull requests, and coordination with every developer who has cloned the repository. Without a complete history rewrite, the key remains accessible indefinitely.

## What Gets Flagged

The rule matches any file (excluding lock files, checksums, and minified assets) that contains the literal string `-----BEGIN PGP PRIVATE KEY BLOCK-----`.

```
# FLAGGED: PGP private key block in any source file
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQIGBGR...
(key data)
-----END PGP PRIVATE KEY BLOCK-----
```

## Remediation

1. **Revoke the key on public keyservers immediately.** Submit a revocation certificate to keys.openpgp.org, keyserver.ubuntu.com, and other keyservers your key was uploaded to. If you do not have a revocation certificate, generate one using the private key while you still have it, then submit it.

2. **Generate a new key pair.** Create a new PGP key pair with a strong passphrase and upload only the public key to keyservers:

```bash
# Generate a new key pair
gpg --full-generate-key

# Export public key only — safe to share
gpg --armor --export you@example.com > public_key.asc

# NEVER export the private key to a file that may be committed
```

3. **Store private keys in the OS keyring or a hardware token.** On developer workstations, GPG stores keys in `~/.gnupg` by default, which is outside the repository. For CI/CD signing, load the key from a CI secret into the keyring at runtime:

```bash
# SAFE: load key from CI secret into keyring — not committed to source
echo "$GPG_PRIVATE_KEY" | gpg --batch --import
echo "$GPG_KEY_ID:6:" | gpg --batch --command-fd 0 --expert --edit-key "$GPG_KEY_ID" trust quit
```

4. **Rewrite git history.** Use `git filter-repo` to remove the file containing the private key from all historical commits, then force-push all branches and tags. All collaborators must re-clone or reset their local repositories after the history rewrite.

## References

- [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [OpenPGP – Key revocation](https://www.openpgp.org/about/)
- [GnuPG – Managing keys](https://www.gnupg.org/gph/en/manual/c235.html)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [GitHub – Generating a new GPG key](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key)
- [git filter-repo documentation](https://htmlpreview.github.io/?https://github.com/newren/git-filter-repo/blob/docs/html/git-filter-repo.html)
