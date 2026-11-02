---
title: "VNX-NODE-023 – Unsafe YAML.load() with untrusted input"
description: "Reports js-yaml 3 load()/loadAll() of request data or an uploaded file without a safe schema, and load() with DEFAULT_FULL_SCHEMA. Not reported: safeLoad, safe schemas, the program's own files, projects on js-yaml 4+, the yaml package, comments and strings."
---

## Overview

In js-yaml 3.x, `load()` and `loadAll()` default to `DEFAULT_FULL_SCHEMA`, which supports the JavaScript-specific types `!!js/regexp`, `!!js/undefined` and `!!js/function`. A `!!js/function` value is compiled with `new Function(...)`, so a document can plant code that runs when the application calls the value or anything coerces it (a `toString` or `valueOf` override). In js-yaml 4.x those types were removed from `load()`, which became the safe loader.

The rule reports a js-yaml `load()`/`loadAll()` call (through a name bound to the module, or imported by name or `as` an alias) with no safe schema whose argument is caller-supplied: a request value or an uploaded file buffer (`req.body/query/params/file(s)`, `ctx.request`, `event.body`, `file.buffer`), directly or through a variable assigned from one within the previous 15 lines, including the call written inside a `vm.runInContext()` script. It also reports `load()` with an explicit `DEFAULT_FULL_SCHEMA` and non-constant input. It does not report `safeLoad()`, a `JSON_SCHEMA`/`CORE_SCHEMA`/`FAILSAFE_SCHEMA`/`DEFAULT_SAFE_SCHEMA` argument, `load()` of the program's own files (a request value that only picks which file to read does not supply the YAML), `load()` without a schema when the project's `package.json` depends on js-yaml 4 or later, or the `yaml` and `yamljs` packages.

**Severity:** High | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

Insecure deserialization is consistently listed in the OWASP Top 10 and has been exploited in numerous real-world supply-chain and application attacks. In the case of js-yaml, a single crafted YAML file — whether submitted via an API, read from a user-supplied path, or embedded in a malicious npm package — can execute arbitrary code in the context of the Node.js process.

YAML is widely used for configuration files, CI/CD pipeline definitions, Kubernetes manifests, and API payloads. Any path that reads YAML from an untrusted source — user uploads, webhook bodies, repository contents fetched from external systems — is a potential injection point. In CI/CD contexts, a compromised YAML pipeline file can execute code with the privileges of the runner, potentially exfiltrating secrets or persisting access.

Upgrading to js-yaml 4.x and using `yaml.load()` with an explicit safe schema, or using `yaml.safeLoad()` in 3.x, eliminates the code execution vector entirely.

## What Gets Flagged

```javascript
// FLAGGED: js-yaml 3 load() of the request body
const yaml = require('js-yaml');
const config = yaml.load(req.body);

// FLAGGED: two-line form from an upload
const text = req.file.buffer.toString('utf8');
const docs = yaml.loadAll(text);

// FLAGGED: the full schema requested explicitly
yaml.load(text, { schema: yaml.DEFAULT_FULL_SCHEMA });

// Not flagged
yaml.safeLoad(req.body);
yaml.load(req.body, { schema: yaml.JSON_SCHEMA });
yaml.load(fs.readFileSync('./swagger.yml', 'utf8'));
```

A YAML document that plants a function:

```yaml
toString: !!js/function >
  function () { return require('child_process').execSync('id').toString(); }
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
