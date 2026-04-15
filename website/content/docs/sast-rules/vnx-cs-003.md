---
title: "VNX-CS-003 – C# XXE via XmlDocument with XmlResolver Enabled"
description: "Detects XML parsing configurations in C# that enable external entity resolution or DTD processing, exposing applications to XML External Entity (XXE) injection attacks."
---

## Overview

This rule detects three unsafe XML parsing configurations in C# code that collectively permit XML External Entity (XXE) injection: setting `XmlResolver` to a `XmlUrlResolver` instance, setting `DtdProcessing` to `Parse`, and setting `ProhibitDtd` to `false`. Any of these configurations allows an XML parser to fetch external resources referenced from within a DTD (Document Type Definition) embedded in the input document.

XXE vulnerabilities arise because the XML standard includes a mechanism — external entities — that instructs the parser to fetch a URI and substitute its contents into the document before processing. When that URI points to a local file path like `file:///etc/passwd`, the contents of that file appear in the parsed document and can be read by the application, then returned to the attacker in an error message or response body. When the URI points to an internal HTTP endpoint, the same mechanism enables Server-Side Request Forgery (SSRF).

Modern .NET XML APIs (XDocument, XmlReader with default settings) disable external entity resolution by default, but older APIs (XmlDocument, XmlTextReader) and explicit configuration changes can re-enable it.

**Severity:** High | **CWE:** [CWE-611 – Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

## Why This Matters

XXE attacks have been in the OWASP Top 10 for over a decade and are responsible for significant data breaches. By crafting a malicious XML document that includes an external entity declaration pointing to a sensitive file, an attacker can exfiltrate `/etc/passwd`, `/etc/shadow`, application configuration files, source code, or cloud instance metadata endpoints (`http://169.254.169.254/`). Depending on the parser's network access, out-of-band XXE can exfiltrate data even when the response is not reflected back.

In .NET applications, XXE is particularly common in SOAP-based web service handlers, file upload processors, and report generation pipelines that parse user-submitted XML. The vulnerability frequently goes undetected because the parser configuration is set once (perhaps buried in a base class or helper method) and then used throughout the codebase. A single misconfigured `XmlDocument` instance used in a deserialization path can expose the entire server's filesystem.

Blind XXE — where the exfiltrated data is sent via a DNS lookup or HTTP request to an attacker-controlled server rather than included in the response — is harder to detect with manual testing but can be found reliably with static analysis rules like this one.

## What Gets Flagged

```csharp
// FLAGGED: XmlUrlResolver explicitly enables external entity fetching
var doc = new XmlDocument();
doc.XmlResolver = new XmlUrlResolver();   // allows file:// and http:// fetches
doc.Load(userInputStream);

// FLAGGED: DtdProcessing.Parse enables full DTD including external entities
var settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Parse;
var reader = XmlReader.Create(userInputStream, settings);

// FLAGGED: ProhibitDtd = false on XmlTextReader (legacy API)
var reader = new XmlTextReader(userInputStream);
reader.ProhibitDtd = false;
```

## Remediation

1. Set `XmlResolver = null` on any `XmlDocument` instance that parses external input — this is the single most important change.
2. Set `DtdProcessing = DtdProcessing.Prohibit` in `XmlReaderSettings` for all reader instances that process untrusted XML.
3. Migrate away from `XmlTextReader` with `ProhibitDtd = false`; use `XmlReader.Create()` with explicit settings instead.
4. Prefer `XDocument.Load()` or `XDocument.Parse()` from `System.Xml.Linq`, which uses `XmlReader` under the hood with safe defaults, for new code.

```csharp
// SAFE: XmlDocument with resolver disabled
var doc = new XmlDocument();
doc.XmlResolver = null;       // disables external entity resolution
doc.Load(userInputStream);

// SAFE: XmlReaderSettings with DTD processing prohibited
var settings = new XmlReaderSettings
{
    DtdProcessing = DtdProcessing.Prohibit,
    XmlResolver = null,
};
using var reader = XmlReader.Create(userInputStream, settings);

// SAFE: XDocument with safe defaults
var xdoc = XDocument.Load(userInputStream);
```

## References

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Microsoft Docs: XML external entity (XXE) injection in .NET](https://learn.microsoft.com/en-us/dotnet/standard/data/xml/xml-security-guidelines)
- [OWASP .NET Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html)
- [CAPEC-221: Data Serialization External Entities Blowup](https://capec.mitre.org/data/definitions/221.html)
