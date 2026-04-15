---
title: "VNX-JAVA-024 – Java XML Entity Expansion (Billion Laughs)"
description: "Detects DocumentBuilderFactory and SAXParserFactory usage without DOCTYPE declarations disabled, leaving the application vulnerable to XML entity expansion denial-of-service attacks."
---

## Overview

The XML specification allows document authors to define entities — symbolic names for repeated text — within a DOCTYPE declaration. When these entity definitions reference each other recursively and the XML parser eagerly expands them, memory and CPU consumption grow exponentially. A single kilobyte of malicious XML can expand to gigabytes of in-memory data before the parser exhausts the JVM heap, causing an out-of-memory crash. This attack, known as the Billion Laughs attack or XML bomb, is described by CWE-776 (Improper Restriction of Recursive Entity References in DTDs).

This rule detects `DocumentBuilderFactory.newInstance()` and `SAXParserFactory.newInstance()` calls in files that do not also contain the `disallow-doctype-decl` feature string or `setExpandEntityReferences(false)`. The absence of these protective features means the parser will process DOCTYPE declarations in untrusted input, enabling the attack.

Beyond entity expansion, the same lack of DOCTYPE hardening leaves the parser vulnerable to XML External Entity (XXE) attacks (CWE-611), where entity references point to file:// URIs or SSRF-capable http:// URIs that can read local files or probe internal services.

**Severity:** High | **CWE:** [CWE-776 – Improper Restriction of Recursive Entity References in DTDs](https://cwe.mitre.org/data/definitions/776.html)

## Why This Matters

Any application that parses XML from external sources — REST API payloads, uploaded documents, message queue bodies, webhook callbacks — is a potential target. The Billion Laughs attack requires no authentication and no knowledge of application internals; the attacker only needs to find an XML parsing endpoint and send a crafted payload.

The attack is reliable because Java's default XML parser configuration is permissive: it honours DOCTYPE declarations, expands entity references, and fetches external entities over the network. This default-permissive stance predates the widespread deployment of internet-facing XML APIs and is now considered a significant design flaw.

Successful XML DoS attacks have been used to disrupt financial transaction processing systems, healthcare data exchange endpoints (HL7/FHIR parsers), and enterprise integration middleware. Recovery from a JVM OOM crash triggered by an XML bomb can take minutes, and if the endpoint is publicly accessible the attack can be repeated faster than the service recovers.

## What Gets Flagged

```java
// FLAGGED: DocumentBuilderFactory without DOCTYPE protection
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(new InputSource(userSuppliedInputStream));

// FLAGGED: SAXParserFactory without security features
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser parser = spf.newSAXParser();
parser.parse(inputStream, handler);
```

## Remediation

1. **Disable DOCTYPE declarations entirely** for parsers that process untrusted input. This is the safest and most complete protection.

2. **If DOCTYPE is required**, disable external entities and entity expansion individually.

3. **Apply the same hardening to SAXParserFactory, XMLInputFactory, and TransformerFactory** — every XML API in the JDK requires independent hardening.

```java
// SAFE: DocumentBuilderFactory with DOCTYPE disabled
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setExpandEntityReferences(false);
dbf.setXIncludeAware(false);
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(trustedSource);
```

```java
// SAFE: SAXParserFactory hardened against entity expansion
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
SAXParser parser = spf.newSAXParser();
parser.parse(inputStream, handler);
```

## References

- [CWE-776: Improper Restriction of Recursive Entity References in DTDs](https://cwe.mitre.org/data/definitions/776.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP XML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_Security_Cheat_Sheet.html)
- [Oracle Java XML Processing Guide](https://docs.oracle.com/en/java/javase/17/docs/api/java.xml/module-summary.html)
- [CAPEC-197: XML Entity Expansion](https://capec.mitre.org/data/definitions/197.html)
