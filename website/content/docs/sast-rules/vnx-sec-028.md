---
title: "VNX-SEC-028 – npm Access Token Hardcoded"
description: "Detect npm access tokens (npm_ prefix) hardcoded in source code, which can be used to publish packages, access private registries, and modify organization settings depending on their scope."
---

## Overview

This rule flags source files containing a string that matches the npm access token format: the prefix `npm_` followed by exactly 36 alphanumeric characters. npm access tokens are used to authenticate with the npm registry for operations such as publishing packages, reading private packages, and modifying organization or team settings. The token's capabilities depend on its type: automation tokens and publish tokens allow package publishing, while read-only tokens are limited to package downloads.

A publish token hardcoded in source code represents one of the most serious supply chain risks in the JavaScript ecosystem. An attacker who obtains a publish token for a widely-used package can release a malicious version that runs arbitrary code on the machines of every developer who installs or updates that package.

This rule corresponds to [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html).

**Severity:** High | **CWE:** [CWE-798 – Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

## Why This Matters

npm package supply chain attacks are a well-documented attack vector with real-world impact. High-profile incidents have demonstrated how a single compromised publish token can result in malicious code being distributed to tens of thousands of downstream projects within hours of a release. The malicious code runs during `npm install` (via lifecycle scripts) or at runtime, exfiltrating secrets, establishing reverse shells, or installing cryptocurrency miners.

Even read-only tokens hardcoded in source represent a risk if the organization uses a private npm registry for proprietary packages. An attacker with read access to the registry can download proprietary code, examine dependencies for further vulnerabilities, and use the registry as a staging point for further attacks.

Token exposure in source code is especially dangerous because npm tokens do not expire by default. A token committed years ago and never rotated remains valid until explicitly revoked.

## What Gets Flagged

The rule matches any file (excluding lock files, checksums, and minified assets) containing a string matching `npm_` followed by 36 alphanumeric characters.

```bash
# FLAGGED: npm token in .npmrc or deployment script
//registry.npmjs.org/:_authToken=npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789

# FLAGGED: token in CI configuration
NPM_TOKEN=npm_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789
```

## Remediation

1. **Revoke the token immediately** at [npmjs.com/settings/tokens](https://www.npmjs.com/settings/tokens). Delete the exposed token and generate a new one with the minimum required scope.

2. **Use an environment variable to provide the token in `.npmrc`.** The standard pattern for CI publishing is to reference an environment variable:

```ini
# SAFE: .npmrc references an environment variable
//registry.npmjs.org/:_authToken=${NPM_TOKEN}
```

3. **Use granular automation tokens.** When publishing from CI/CD, use an automation token rather than a full-access token. Automation tokens bypass 2FA requirements for CI but are otherwise scoped to publishing only:

```bash
# SAFE: generate an automation token with minimal scope
npm token create --type=automation --cidr-whitelist=203.0.113.0/24
```

4. **Enable npm Provenance.** When publishing from GitHub Actions, use npm's provenance feature to link published packages to the CI run, reducing the value of a stolen token since publications can be attributed and audited:

```yaml
# SAFE: publish with provenance from GitHub Actions
- name: Publish to npm
  run: npm publish --provenance
  env:
    NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [npm – Access tokens documentation](https://docs.npmjs.com/about-access-tokens)
- [npm – Generating and using access tokens](https://docs.npmjs.com/creating-and-viewing-access-tokens)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [npm – Provenance and package signing](https://docs.npmjs.com/generating-provenance-statements)
