---
title: "VNX-PY-014 – Python XML External Entity (XXE) Injection"
description: "Detect Python XML parsers configured to resolve external entities (SAX external-entity features on, lxml resolve_entities=True or no_network=False, xmltodict disable_entities=False) or lxml parsing request data with the default parser, which can expose local files and internal network resources (XXE)."
---

## Overview

This rule flags XML parsers that are configured, or used, so that they resolve external entities: a SAX parser with `feature_external_ges`/`feature_external_pes` switched on (which minidom and pulldom then inherit), an lxml `XMLParser(resolve_entities=True)` or `no_network=False`, `xmltodict.parse(..., disable_entities=False)`, and lxml `etree.fromstring`/`XML`/`parse` given request data with no explicit parser. The standard library's `xml.etree`, `minidom` and `sax` parsers with their defaults are not reported, because current Python does not fetch external entities with them. When an XML parser processes an external entity declaration (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`), it fetches and substitutes the referenced resource. This allows an attacker who can provide XML input to read arbitrary local files, probe internal network services, or cause denial of service via entity expansion. This maps to [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html).

**Severity:** High | **CWE:** [CWE-611 – XML External Entity (XXE)](https://cwe.mitre.org/data/definitions/611.html)

## Why This Matters

XXE is a serious vulnerability because it allows attackers to read files outside the web root using only a crafted XML document. In a typical attack the payload looks like:

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>
```

When parsed without XXE protections, the server substitutes the contents of `/etc/passwd` into the document. The attacker receives this in the response (in an exfiltration scenario) or can infer it through error messages or timing (in a blind XXE scenario). High-value targets include:

- `/etc/passwd` and `/etc/shadow` — user account enumeration
- Application configuration files — database credentials, API keys, `SECRET_KEY`
- `/proc/self/environ` — process environment variables (secrets, tokens)
- Internal HTTP endpoints — `http://169.254.169.254/` (cloud metadata service) for credentials or instance identity

Python's `xml.etree.ElementTree` documentation states it is not secure against maliciously constructed data, but on current Python its default parsers do not fetch external entities; entity expansion (billion laughs) remains a separate denial-of-service concern that this rule does not cover. External entities become reachable when a parser is explicitly configured to resolve them, or with lxml's default parser on older releases.

## What Gets Flagged

```python
# FLAGGED: SAX external entities switched on (minidom/pulldom inherit this)
from xml.sax.handler import feature_external_ges
parser = xml.sax.make_parser()
parser.setFeature(feature_external_ges, True)

# FLAGGED: lxml parser that resolves entities or reaches the network
from lxml import etree
parser = etree.XMLParser(resolve_entities=True)
parser = etree.XMLParser(no_network=False)

# FLAGGED: xmltodict with entities enabled
doc = xmltodict.parse(body, disable_entities=False)

# FLAGGED: lxml parsing request data with the default parser
root = etree.fromstring(request.data)

# NOT flagged: stdlib defaults, defusedxml, an explicit safe parser
root = xml.etree.ElementTree.fromstring(body)
root = defusedxml.ElementTree.fromstring(body)
root = etree.fromstring(request.data, etree.XMLParser(resolve_entities=False))
```

## Remediation

1. **Use the `defusedxml` package as a drop-in replacement.** `defusedxml` is a Python package that wraps all stdlib XML parsers and disables external entity processing, DTD processing, and related attack vectors. The API is identical to the stdlib modules:

```python
# Install: pip install defusedxml
import defusedxml.ElementTree as ET

# SAFE: defusedxml disables external entities, DTDs, and entity expansion
tree = ET.parse("data.xml")
root = ET.fromstring(xml_string)
```

```python
import defusedxml.minidom as minidom

# SAFE: same API as xml.dom.minidom but safe
doc = minidom.parse("document.xml")
doc = minidom.parseString(xml_bytes)
```

```python
import defusedxml.sax as sax

# SAFE: SAX parser with external entities disabled
sax.parse("data.xml", handler)
```

2. **For lxml, create an `XMLParser` with external entity resolution disabled.**

```python
from lxml import etree

# SAFE: no_network=True disables network fetches; resolve_entities=False disables XXE
safe_parser = etree.XMLParser(
    no_network=True,
    resolve_entities=False,
    load_dtd=False,
)
tree = etree.parse("data.xml", safe_parser)
root = etree.fromstring(xml_string, safe_parser)
```

3. **For XML that does not require entity support, use a streaming JSON alternative.** If you control the data format, switching from XML to JSON eliminates the entire XXE attack surface:

```python
import json

# SAFE: JSON has no concept of external entities
data = json.loads(request.body)
```

4. **Validate XML structure after parsing.** Even with safe parsers, validate the structure of the parsed document against an XML Schema (XSD) or Relax NG schema before using its values. This catches malformed documents and unexpected element structures:

```python
from lxml import etree

schema_doc = etree.parse("schema.xsd")
schema = etree.XMLSchema(schema_doc)

safe_parser = etree.XMLParser(no_network=True, resolve_entities=False)
doc = etree.parse("data.xml", safe_parser)

if not schema.validate(doc):
    raise ValueError(f"XML validation failed: {schema.error_log}")
```

5. **Never parse XML from untrusted sources with the standard library parsers.** The Python documentation explicitly warns about this. Treat any XML arriving from a network endpoint, file upload, webhook, or database field as untrusted and route it through `defusedxml` or a hardened lxml parser.

## References

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [OWASP Top 10 A05:2021 – Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [Python docs – xml security warning (defusedxml)](https://docs.python.org/3/library/xml.html#xml-vulnerabilities)
- [defusedxml documentation](https://github.com/tiran/defusedxml)
- [lxml documentation – XMLParser](https://lxml.de/parsing.html#parsers)
- [CAPEC-201: XML Entity Linking](https://capec.mitre.org/data/definitions/201.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
