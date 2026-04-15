---
title: "VNX-JAVA-004 – XML External Entity (XXE) Injection"
description: "Detects Java XML parsers instantiated without XXE protection features, enabling attackers to read arbitrary server files, trigger SSRF, or cause denial of service via entity expansion."
---

## Overview

This rule detects instantiation of Java XML parser factories — `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, and `SchemaFactory` — in files that do not also configure the features required to disable external entity resolution. Without these protections, any XML document processed by the parser can include an external entity declaration that causes the parser to fetch a remote URL or a local file path, disclosing the result to the attacker. This is XML External Entity injection, CWE-611.

**Severity:** High | **CWE:** [CWE-611 – Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)

## Why This Matters

XXE is a deceptively simple attack. An attacker submits an XML document containing a DOCTYPE declaration that defines an entity whose value is a `file:///etc/passwd` URI. The parser resolves the entity, reads the file, and substitutes its content into the document — which the application may then echo back in an error message, an API response, or a log entry. The same technique works against `file:///proc/self/environ` (environment variables), private key files, and application configuration files containing database credentials.

Beyond file disclosure, an attacker can use `http://` entities to make the server issue HTTP requests to internal addresses (SSRF), probe internal ports, and in some configurations interact with services that speak non-HTTP protocols by exploiting `gopher://` support. The "Billion Laughs" variant uses nested entity expansion to exhaust parser memory and crash the service (denial of service). XXE has appeared in high-profile CVEs against enterprise Java frameworks including Spring MVC, Apache Solr, and various SOAP stacks.

## What Gets Flagged

The rule matches `.java` files that instantiate any of the five XML parser factories but do not contain any of the three protective configuration strings: `disallow-doctype-decl`, `FEATURE_SECURE_PROCESSING`, or `external-general-entities`.

```java
// FLAGGED: DocumentBuilderFactory without external entity protection
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(inputStream);  // reads attacker-controlled XML

// FLAGGED: SAXParserFactory without protection
SAXParserFactory spf = SAXParserFactory.newInstance();
SAXParser parser = spf.newSAXParser();
parser.parse(request.getInputStream(), handler);
```

## Remediation

The preferred fix for `DocumentBuilderFactory` is to enable the `disallow-doctype-decl` feature. This causes the parser to throw an exception as soon as it encounters any DOCTYPE declaration, completely eliminating the XXE attack surface. For parsers that legitimately need DOCTYPE support (e.g. for validation), disable only external entities and external parameter entities individually.

1. **Disable DOCTYPE declarations entirely (recommended):**

   ```java
   // SAFE: DOCTYPE declarations are rejected outright
   DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
   dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   dbf.setXIncludeAware(false);
   dbf.setExpandEntityReferences(false);
   DocumentBuilder db = dbf.newDocumentBuilder();
   Document doc = db.parse(inputStream);
   ```

2. **Disable external entities individually when DOCTYPE is required:**

   ```java
   // SAFE: external entity resolution disabled, DOCTYPE still allowed
   DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
   dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
   dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
   dbf.setXIncludeAware(false);
   dbf.setExpandEntityReferences(false);
   DocumentBuilder db = dbf.newDocumentBuilder();
   ```

3. **Secure `SAXParserFactory`:**

   ```java
   // SAFE: SAX parser with XXE protection
   SAXParserFactory spf = SAXParserFactory.newInstance();
   spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
   spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
   spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
   SAXParser parser = spf.newSAXParser();
   ```

4. **Secure `XMLInputFactory` (StAX):**

   ```java
   // SAFE: StAX parser with XXE protection
   XMLInputFactory xif = XMLInputFactory.newInstance();
   xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
   xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
   XMLStreamReader reader = xif.createXMLStreamReader(inputStream);
   ```

5. **Use a high-level XML library with secure defaults.** Libraries like `JAXB` (in modern versions), Jackson's `XmlMapper`, or `dom4j` (when configured correctly) can be easier to secure than raw factory configuration. Check the library's documentation for its XXE stance.

6. **Consider using JSON instead of XML** for new API designs. JSON parsers do not have entity resolution mechanisms and are not vulnerable to XXE.

## References

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [CAPEC-201: XML Entity Expansion](https://capec.mitre.org/data/definitions/201.html)
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [OWASP ASVS V5 – Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
- [Java XML Processing – Oracle Security Guide](https://docs.oracle.com/en/java/javase/21/security/java-api-xml-processing-jaxp-security-guide.html)
