---
title: "VNX-PHP-013 – PHP XXE via LIBXML_NOENT or LIBXML_DTDLOAD flag"
description: "Detects simplexml_load_string() or simplexml_load_file() called with LIBXML_NOENT or LIBXML_DTDLOAD flags, which enable XML external entity expansion and can expose arbitrary server files."
---

## Overview

This rule detects calls to `simplexml_load_string()` or `simplexml_load_file()` that pass the `LIBXML_NOENT` or `LIBXML_DTDLOAD` flags. `LIBXML_NOENT` instructs the parser to substitute XML entity references — including external entities that reference file paths and URLs — with their declared values. `LIBXML_DTDLOAD` enables loading of external Document Type Definition files, which in turn can declare external entities.

An XML External Entity (XXE) attack works by embedding a DTD in the XML document that declares an entity pointing to a local file (`file:///etc/passwd`) or a remote URL. When the parser processes the document with entity expansion enabled, the content of the referenced resource is injected into the XML data and may be returned in the application's response or used in a way that leaks it to the attacker.

PHP's libxml-based parsers (`simplexml`, `DOMDocument`, `XMLReader`) all share the same underlying entity loader. The `libxml_disable_entity_loader(true)` function (available in PHP versions before 8.0, where it became a no-op as loading is disabled by default) globally prevents external entity loading for the current request.

**Severity:** High | **CWE:** [CWE-611 – Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

## Why This Matters

XXE has appeared on the OWASP Top 10 and has been exploited in high-profile attacks against financial services, healthcare, and government systems. The vulnerability is especially dangerous because it operates at the parser level — before any application logic runs — and can expose files the application has never explicitly tried to read.

Common targets in XXE attacks include `/etc/passwd` and `/etc/shadow` for credential enumeration, application configuration files containing database credentials, SSH private keys, cloud metadata endpoints (`http://169.254.169.254/latest/meta-data/`) for IAM credential theft, and internal network services accessible from the server (SSRF).

PHP applications that process SAML assertions, RSS/Atom feeds, Office Open XML documents, or any XML-based API integration are at risk. SAML-based single sign-on is a particularly high-value target because XXE in the SAML parser can enable authentication bypass.

## What Gets Flagged

```php
// FLAGGED: LIBXML_NOENT enables entity substitution — exposes local files
$xml = simplexml_load_string($userInput, 'SimpleXMLElement', LIBXML_NOENT);

// FLAGGED: LIBXML_DTDLOAD enables external DTD, which can declare entities
$doc = simplexml_load_file($uploadedFile, 'SimpleXMLElement', LIBXML_DTDLOAD);
```

A malicious XML payload:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY secret SYSTEM "file:///etc/passwd">
]>
<root>&secret;</root>
```

## Remediation

1. **Remove `LIBXML_NOENT` and `LIBXML_DTDLOAD` flags** from all `simplexml_load_*` and `DOMDocument::loadXML()` calls.

2. **Call `libxml_disable_entity_loader(true)`** at the start of any request that parses XML (for PHP versions before 8.0).

3. **In PHP 8.0+**, external entity loading is disabled by default — ensure you have not re-enabled it with `libxml_set_external_entity_loader()`.

4. **Validate that XML documents do not contain DOCTYPE declarations** when your protocol does not require them — reject any document that includes a `<!DOCTYPE>` element.

```php
<?php
// SAFE: entity loader disabled and dangerous flags omitted
if (PHP_VERSION_ID < 80000) {
    libxml_disable_entity_loader(true);
}

$xml = simplexml_load_string(
    $userInput,
    'SimpleXMLElement',
    LIBXML_NOERROR | LIBXML_NOWARNING  // no LIBXML_NOENT or LIBXML_DTDLOAD
);

if ($xml === false) {
    throw new InvalidArgumentException('Invalid XML input');
}
```

## References

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CAPEC-221: Data Serialization External Entities Blowup](https://capec.mitre.org/data/definitions/221.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP PHP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [PHP Manual – libxml_disable_entity_loader()](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php)
- [PortSwigger Web Security Academy – XXE Injection](https://portswigger.net/web-security/xxe)
