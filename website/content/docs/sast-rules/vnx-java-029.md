---
title: "VNX-JAVA-029 – XML External Entity (XXE) via DocumentBuilderFactory"
description: "Detects XML parsers created via DocumentBuilderFactory, SAXParserFactory, or XMLReader that do not disable external entity processing, leaving them open to XXE attacks."
---

## Overview

This rule detects instantiation of `DocumentBuilderFactory`, `SAXParserFactory`, or `XMLReader` without the corresponding `setFeature()` calls that disable external entity (XXE) processing. By default, many JDK XML parser implementations will resolve external entity references declared in a document's DTD. When an application parses untrusted XML with these defaults, an attacker can supply a crafted XML document that causes the parser to read local files, make outbound network requests, or exhaust server resources through entity expansion (Billion Laughs). This vulnerability is classified as CWE-611 (Improper Restriction of XML External Entity Reference).

The Java standard library ships with multiple XML parsing APIs — DOM (`DocumentBuilderFactory`), SAX (`SAXParserFactory`), and StAX — each with its own feature flags for controlling entity processing. Configuring each correctly requires explicit, non-obvious `setFeature()` calls that are easy to omit, especially when copying boilerplate parsing code. JDK versions prior to 8u191 had XXE-safe defaults in some APIs but not others; relying on JDK version for safety is fragile.

**Severity:** High | **CWE:** [CWE-611 – Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html) | **OWASP:** [A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/) | **CAPEC:** [CAPEC-183 – IMAP/SMTP Command Injection](https://capec.mitre.org/data/definitions/183.html) | **ATT&CK:** [T1195.002](https://attack.mitre.org/techniques/T1195/002/)

## Why This Matters

XXE attacks can lead to server-side file disclosure (`/etc/passwd`, application config files, private keys), Server-Side Request Forgery (SSRF) to internal services including cloud metadata endpoints, denial of service via recursive entity expansion, and in some configurations remote code execution. SAML authentication libraries parsing XML assertions have historically been prime XXE targets — a successful XXE in a SAML processor can lead to complete authentication bypass.

The impact is amplified in containerized or cloud environments where the application process has access to instance metadata services (AWS `http://169.254.169.254`, GCP, Azure equivalents). An attacker who retrieves IAM credentials via XXE gains the cloud permissions of the application's service identity, potentially enabling lateral movement across the entire cloud account.

## What Gets Flagged

```java
// FLAGGED: DocumentBuilderFactory with no XXE mitigations
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(req.getInputStream()));

// FLAGGED: SAXParserFactory without feature hardening
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser parser = spf.newSAXParser();
parser.parse(inputStream, handler);

// FLAGGED: XMLReader without disabling external entities
XMLReader reader = XMLReaderFactory.createXMLReader();
reader.parse(new InputSource(untrustedInput));
```

## Remediation

1. Set `http://apache.org/xml/features/disallow-doctype-decl` to `true` on the factory. This is the most complete mitigation — it rejects any XML document containing a DOCTYPE declaration, eliminating the attack surface entirely.
2. If DOCTYPE is required, additionally disable external general and parameter entities via their respective feature flags.
3. Wrap `setFeature()` calls in a try/catch for `ParserConfigurationException` to handle JDK implementations that do not support a specific feature string — fail closed by throwing an exception rather than continuing with an unsafe parser.
4. Consider using a safe wrapper library (OWASP's XML security utilities) that applies hardened defaults automatically.

```java
// SAFE: DocumentBuilderFactory with XXE disabled
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Disallow DOCTYPE entirely — most complete protection
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// Belt-and-suspenders: also disable external entities if DOCTYPE slips through
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(req.getInputStream()));

// SAFE: SAXParserFactory equivalent
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
SAXParser parser = spf.newSAXParser();
```

## References

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CAPEC-183: XML External Entities Blowup](https://capec.mitre.org/data/definitions/183.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP XML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html)
- [PortSwigger Web Security Academy — XXE Injection](https://portswigger.net/web-security/xxe)
- [Oracle Java SE Security: Secure XML Processing](https://docs.oracle.com/en/java/javase/17/security/java-xml-digital-signature-api-overview-and-tutorial.html)
