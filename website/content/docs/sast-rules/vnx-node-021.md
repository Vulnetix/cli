---
title: "VNX-NODE-021 – XXE via libxmljs with noent:true"
description: "Detects libxmljs or libxmljs2 XML parsing with the noent option set to true, enabling XML External Entity (XXE) attacks that can read arbitrary server files or trigger SSRF."
---

## Overview

This rule detects two patterns involving the `libxmljs` and `libxmljs2` Node.js XML parsing libraries: any call that enables external entity expansion via `noent: true`, and any import of these libraries (as a warning, prompting review). When `noent` is set to `true`, the XML parser resolves and expands external entity declarations in the Document Type Definition (DTD), which can reference local file paths or remote URLs.

An XML External Entity attack begins with a crafted XML document containing a DTD that declares an entity pointing to a sensitive file (e.g., `file:///etc/passwd`) or a network-accessible service. When the application parses this document with entity expansion enabled, the content of the referenced resource is injected into the XML document body and returned in the response, or processed in a way that leaks it to the attacker.

The `noent` option specifically enables entity substitution — it is the parameter that must be `false` when parsing untrusted XML. Similarly, `dtdload` should not be enabled as it allows loading external DTD files, which in turn can declare external entities.

**Severity:** High | **CWE:** [CWE-611 – Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

## Why This Matters

XXE has appeared in the OWASP Top 10 for multiple consecutive cycles and has been exploited in significant real-world incidents. The attack allows unauthenticated file disclosure — an attacker with the ability to send XML to the application can read any file readable by the Node.js process, including `/etc/passwd`, SSH private keys, application configuration files with database credentials, and cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`).

The SSRF variant of XXE is particularly dangerous in cloud environments: the cloud instance metadata service is accessible from the server and returns temporary IAM credentials with significant privileges. An attacker who retrieves these credentials via XXE SSRF gains the cloud permissions of the application's service account.

`libxmljs` is less commonly used than browser-native XML parsing but appears in document processing pipelines, XML-based API integrations, and SAML assertion parsing. SAML parsing is a high-value target because XXE in a SAML processor can allow authentication bypass — the attacker injects XML that evaluates to a legitimate user's assertion.

## What Gets Flagged

```javascript
// FLAGGED: noent:true enables external entity expansion
const libxml = require('libxmljs');
const doc = libxml.parseXmlString(req.body.xmlData, { noent: true });

// FLAGGED: parseXml with noent:true on user input
const doc = libxml.parseXml(xmlBuffer, { noent: true, dtdload: true });

// FLAGGED (warning): libxmljs imported — review all parse calls for noent
const libxmljs = require('libxmljs2');
```

A malicious XML payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

## Remediation

1. **Set `noent: false`** (or omit the option entirely, as `false` is the default) in all `parseXmlString()` and `parseXml()` calls.

2. **Set `dtdload: false` and `dtdvalid: false`** to prevent loading external DTDs that could declare external entities.

3. **Validate that user-supplied XML is structurally expected** before parsing — reject documents with DOCTYPE declarations when they are not required by your protocol.

4. **Consider switching to a DTD-free XML format** or a JSON equivalent if your integration does not require XML.

```javascript
// SAFE: parse with entity expansion disabled (secure defaults)
const libxml = require('libxmljs2');

function safeParseXml(xmlString) {
  return libxml.parseXmlString(xmlString, {
    noent:    false,  // do not expand external entities
    dtdload:  false,  // do not load external DTDs
    dtdvalid: false,  // do not validate against DTD
    nonet:    true,   // do not access network resources during parse
  });
}

app.post('/xml', express.text({ type: 'application/xml' }), (req, res) => {
  let doc;
  try {
    doc = safeParseXml(req.body);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid XML' });
  }
  // process doc safely
});
```

## References

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CAPEC-221: Data Serialization External Entities Blowup](https://capec.mitre.org/data/definitions/221.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Node.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html)
- [libxmljs2 npm package](https://www.npmjs.com/package/libxmljs2)
- [PortSwigger Web Security Academy — XXE Injection](https://portswigger.net/web-security/xxe)
