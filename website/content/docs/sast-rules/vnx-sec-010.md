---
title: "VNX-SEC-010 – Package Registry Token"
description: "Detects hardcoded npm access tokens (npm_ prefix) and PyPI upload tokens in source code, which grant publish access to package registries and enable supply chain attacks."
---

## Overview

This rule detects npm access tokens matching `npm_[0-9a-zA-Z]{36}` and PyPI upload tokens matching `pypi-AgEIcHlwaS5vcmc[0-9A-Za-z\-_]{50,}` in source files. These tokens authenticate publish operations to package registries. A compromised publish token allows an attacker to release a malicious version of any package the token owner controls, potentially affecting every downstream user of that package — a textbook supply chain attack mapped to MITRE ATT&CK T1195.002.

**Severity:** Critical | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

Package registry tokens are among the most dangerous credentials to expose because their impact extends far beyond the token owner. A single leaked npm publish token can be used to inject malicious code into a package that is downloaded by thousands or millions of developers and end users. The 2021 `ua-parser-js` and `coa` hijacking incidents demonstrated exactly this attack: malicious versions containing credential stealers were published to npm and downloaded hundreds of thousands of times before detection.

PyPI tokens similarly control package distribution for the Python ecosystem. A token with upload access to a popular package can introduce a backdoor that persists across any application that installs the package.

npm token types and their risk:
- **Automation tokens** (`npm_...`): Bypass 2FA for CI/CD use — highest publish risk
- **Publish tokens**: Require 2FA for interactive use but allow publishing
- **Read-only tokens**: Lower risk but still expose package metadata

## What Gets Flagged

```ini
# FLAGGED: npm token hardcoded in .npmrc
//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

```python
# FLAGGED: PyPI token in setup script or CI config
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmcxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

```yaml
# FLAGGED: npm token in workflow file
- name: Publish
  run: npm publish
  env:
    NODE_AUTH_TOKEN: npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## Remediation

1. **Revoke the token immediately.** For npm: go to npmjs.com → Account Settings → Access Tokens → find the token → Delete. For PyPI: go to pypi.org → Account Settings → API tokens → Revoke.

2. **Audit for unauthorized package publishes.** Check the package's version history on the registry to verify no unexpected versions were released. For npm: `npm view <package> time`. For PyPI: check the package's release history on pypi.org.

3. **Remove from source code.** Use environment variable substitution in `.npmrc`:

```ini
# SAFE: .npmrc using environment variable (commit this file)
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

```yaml
# SAFE: GitHub Actions workflow using secrets
- name: Publish to npm
  uses: actions/setup-node@v4
  with:
    node-version: '20'
    registry-url: 'https://registry.npmjs.org'
- run: npm publish
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

```bash
# SAFE: PyPI publish using Twine with environment variable
export TWINE_USERNAME=__token__
export TWINE_PASSWORD="${PYPI_TOKEN}"
twine upload dist/*
```

4. **Use OIDC-based trusted publishing for PyPI.** GitHub Actions, GitLab CI, and other CI providers can publish to PyPI without storing a token at all using OpenID Connect trusted publishing:

```yaml
# SAFE: PyPI trusted publishing via GitHub Actions OIDC (no token needed)
- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    attestations: true
```

5. **Create scoped tokens for CI/CD.** For npm, create an automation token with the minimum required scope. For npm packages, consider using `npm token create --cidr=203.0.113.0/24` to restrict usage by IP.

6. **Enable npm package provenance.** npm supports SLSA-level package provenance linked to GitHub Actions workflows, making it much harder to publish malicious packages from outside your trusted CI environment.

7. **Scan git history** for exposed tokens:

```bash
gitleaks detect --source . --verbose
git filter-repo --replace-text <(echo 'npm_xxxx==>REDACTED_NPM_TOKEN')
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [npm: Access tokens documentation](https://docs.npmjs.com/about-access-tokens)
- [PyPI: API tokens](https://pypi.org/help/#apitoken)
- [PyPI: Trusted publishers](https://docs.pypi.org/trusted-publishers/)
- [npm: Package provenance](https://docs.npmjs.com/generating-provenance-statements)
- [OWASP: Software Supply Chain Security](https://owasp.org/www-project-software-supply-chain-security/)
- [MITRE ATT&CK T1195.002 – Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/)
