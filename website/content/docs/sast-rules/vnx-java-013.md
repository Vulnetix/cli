---
title: "VNX-JAVA-013 – Java XPath Injection"
description: "Detect Java code that constructs XPath expressions from user input via xpath.evaluate() or xpath.compile() with string concatenation, enabling data extraction and authentication bypass."
---

## Overview

This rule flags Java code where `xpath.evaluate()` or `xpath.compile()` receives user-controlled input from HTTP request parameters, or where XPath expressions are built using string concatenation. An attacker can manipulate the query structure to bypass authentication, extract unauthorized data, or enumerate the XML document structure. This maps to [CWE-643: Improper Neutralization of Data within XPath Expressions](https://cwe.mitre.org/data/definitions/643.html).

**Severity:** High | **CWE:** [CWE-643 – XPath Injection](https://cwe.mitre.org/data/definitions/643.html)

## Why This Matters

When user input is interpolated into XPath expressions, an attacker can inject XPath operators to modify query logic. An authentication query like `//user[name='INPUT' and pass='INPUT']` can be bypassed with `' or '1'='1` to select all users. XPath injection gives read access to the entire XML document tree — there is no per-table permissions concept like in SQL databases.

## What Gets Flagged

```java
// FLAGGED: XPath with user input and string concatenation
String user = request.getParameter("user");
xpath.evaluate("//users/user[name='" + user + "']", doc, XPathConstants.NODESET);
```

## Remediation

1. **Use XPath variable resolvers for parameterized queries:**

```java
// SAFE: parameterized XPath with variable resolver
xpath.setXPathVariableResolver(variableName -> {
    if ("username".equals(variableName.getLocalPart())) {
        return request.getParameter("user");
    }
    return null;
});
xpath.evaluate("//users/user[name=$username]", doc, XPathConstants.NODESET);
```

2. **Validate input against a strict allowlist** before using in XPath expressions.

## References

- [CWE-643: Improper Neutralization of Data within XPath Expressions](https://cwe.mitre.org/data/definitions/643.html)
- [OWASP XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection)
- [Java javax.xml.xpath API](https://docs.oracle.com/en/java/javase/17/docs/api/java.xml/javax/xml/xpath/package-summary.html)
- [CAPEC-83: XPath Injection](https://capec.mitre.org/data/definitions/83.html)
