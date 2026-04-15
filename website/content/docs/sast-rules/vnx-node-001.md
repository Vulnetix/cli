---
title: "VNX-NODE-001 – Missing npm Lock File"
description: "No package-lock.json, yarn.lock, or pnpm-lock.yaml found alongside package.json, enabling dependency confusion and supply chain attacks."
---

## Overview

This rule detects Node.js projects that have a `package.json` but no corresponding lock file (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`). Without a lock file, every `npm install` re-resolves floating version ranges from the registry, meaning a different — potentially malicious — package version may be installed on each run. This falls under CWE-829 (Inclusion of Functionality from Untrusted Control Sphere) and directly enables dependency confusion and supply chain attacks.

**Severity:** High | **CWE:** [CWE-829 – Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html) | **OWASP ASVS:** V10.3.2

Lock files are **not generated automatically** by Node.js or npm. You must run `npm install`, `yarn install`, or `pnpm install` explicitly to create one, and then commit it to version control. Without this step, your dependency tree is non-deterministic across environments.

## Why This Matters

In a dependency confusion attack, an adversary publishes a public package with the same name as one of your internal packages but a higher version number. Without a lock file pinning exact resolved versions, `npm install` may silently pull the malicious public package instead of your internal one. The 2021 dependency confusion attack by security researcher Alex Birsan demonstrated this against Apple, Microsoft, and dozens of other companies — every affected project lacked pinned dependencies.

Beyond malicious substitution, floating ranges mean that a legitimate upstream package can introduce a breaking change or a newly discovered vulnerability between your CI run and your production deploy. A lock file makes builds reproducible and auditable: you can review exactly what changed between two lock file commits rather than discovering version drift at runtime.

OWASP ASVS v4 requirement **V10.3.2** states: "Verify that the application only uses software components without known vulnerabilities." Pinning dependencies via a lock file is a prerequisite for this — you cannot audit what you cannot enumerate.

## What Gets Flagged

The rule fires when a directory is identified as a Node.js project (it appears in `dirs_by_language["node"]`) but none of the three standard lock files exist alongside `package.json`.

```
my-service/
  package.json       ← project root detected
  src/
  ...
  # FLAGGED: no package-lock.json, yarn.lock, or pnpm-lock.yaml present
```

## Remediation

1. **Generate a lock file immediately.** Run the package manager you already use:

   ```bash
   # npm (creates package-lock.json)
   npm install

   # yarn (creates yarn.lock)
   yarn install

   # pnpm (creates pnpm-lock.yaml)
   pnpm install
   ```

2. **Commit the lock file to version control.** The lock file must live in the repository root (or the relevant workspace root) and be committed alongside `package.json`. Never add lock files to `.gitignore`.

3. **Use `npm ci` instead of `npm install` in CI/CD.** `npm ci` installs exactly what is in `package-lock.json`, fails if the lock file is absent or out of sync with `package.json`, and never modifies the lock file. This guarantees reproducible builds across environments.

   ```bash
   # SAFE: reproducible CI install
   npm ci

   # In a Dockerfile:
   COPY package.json package-lock.json ./
   RUN npm ci --omit=dev
   ```

4. **Pin to lock file version 2 or higher.** `package-lock.json` version 2+ (npm 7+) includes an `integrity` field with SRI hashes for every resolved package. Verify the npm version in your pipeline:

   ```bash
   node -e "console.log(JSON.parse(require('fs').readFileSync('package-lock.json')).lockfileVersion)"
   # Should print 2 or 3
   ```

5. **Enable `npm audit` in CI.** Running `npm audit --audit-level=high` after `npm ci` catches newly disclosed vulnerabilities in your pinned dependency tree before they reach production.

   ```bash
   npm ci
   npm audit --audit-level=high
   ```

6. **Consider private registry mirroring.** For high-security environments, mirror required packages to a private Artifact Registry or Nexus instance and configure npm to resolve only from that registry, eliminating the public-registry attack surface entirely.

   ```bash
   # .npmrc — scope private packages to internal registry
   @myorg:registry=https://npm.internal.example.com
   ```

## References

- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [CAPEC-185: Malicious Software Download](https://capec.mitre.org/data/definitions/185.html)
- [OWASP ASVS v4 – V10.3.2 Software Integrity](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [npm ci documentation](https://docs.npmjs.com/cli/v10/commands/npm-ci)
- [npm package-lock.json specification](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json)
- [Alex Birsan – Dependency Confusion attack writeup](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [MITRE ATT&CK T1195.001 – Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/)
