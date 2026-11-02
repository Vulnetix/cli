---
id: "VNX-91"
title: "VNX-91 – XML Injection"
description: "An XML document is assembled as text with an HTTP request value spliced into a tag literal (concatenation, interpolation, format strings), in a file that works with XML, so the value can rewrite the document's structure."
---

## Overview

VNX-91 maps to [CWE-91: XML Injection (aka Blind XPath Injection)](https://cwe.mitre.org/data/definitions/91.html). It reports a line that builds XML text from a string literal holding a tag and a request value, directly or through a variable assigned from the request in the 15 lines above, in a file that parses, sends or declares XML.

**Severity:** Medium | **CWE:** [CWE-91](https://cwe.mitre.org/data/definitions/91.html) | **Languages:** go, java, node, php, python, ruby

## Why This Matters

A value like `bob</name><role>admin</role><name>` closes the element it was meant to fill and adds new ones. The parser, a SOAP service or a downstream system then trusts structure the attacker wrote: an extra role, a changed price, a second order line, or an entity declaration that turns into XXE.

## What Gets Flagged

```java
String xml = "<user><name>" + request.getParameter("name") + "</name>";
```

```python
doc = etree.fromstring(f"<order><id>{request.args['id']}</id></order>")
line = "<qty>%s</qty>" % qty          # qty = request.form.get("qty")
```

```javascript
const body = `<?xml version="1.0"?><soap:Envelope>...<name>${req.body.name}</name>...`;
```

```php
$xml = "<user><name>" . $_POST['name'] . "</name></user>";
$title = "<title>$c</title>";           // $c = $_REQUEST['title'];
```

```go
body := fmt.Sprintf("<invoice><customer>%s</customer></invoice>", r.FormValue("customer"))
```

```ruby
xml = "<feed><title>#{params[:title]}</title></feed>"
```

Not flagged: values passed through an XML or HTML escaper (`escape`, `StringEscapeUtils.escapeXml10`, `htmlspecialchars`, `html.EscapeString`, `CGI.escapeHTML`), documents built with a DOM, ElementTree or builder API, markup built in files that never touch XML (HTML output is reported by the XSS rules), constant documents and comments. XPath query injection is reported by VNX-643 and VNX-JAVA-013.

## Remediation

1. Build XML with an API that sets text content: `createElement` + `setTextContent`, `ET.SubElement(...).text`, `xmlbuilder`, `Nokogiri::XML::Builder`, `encoding/xml` marshalling.
2. If text must be concatenated, XML-escape every inserted value (`&`, `<`, `>`, `"`, `'`).
3. Validate the resulting document against a schema before acting on it.

## References

- [CWE-91: XML Injection](https://cwe.mitre.org/data/definitions/91.html)
- [OWASP Testing for XML Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection)
