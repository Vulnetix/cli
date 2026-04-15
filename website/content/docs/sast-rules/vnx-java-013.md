---
title: "VNX-JAVA-013 – Java XPath Injection"
description: "Detects Java code that constructs XPath expressions from user input via xpath.evaluate() or xpath.compile() with request parameters or string concatenation, enabling XML data extraction and authentication bypass."
---

## Overview

This rule flags Java code where `xpath.evaluate()` or `xpath.compile()` receives user-controlled input from HTTP request parameters, or where XPath expressions are assembled using string concatenation (`+`). An attacker can manipulate the injected expression to bypass authentication checks, extract all data from the underlying XML document, or enumerate its structure. This is [CWE-643: Improper Neutralization of Data within XPath Expressions](https://cwe.mitre.org/data/definitions/643.html).

**Severity:** High | **CWE:** [CWE-643 – XPath Injection](https://cwe.mitre.org/data/definitions/643.html)

## Why This Matters

XPath expressions describe paths through an XML document tree. When user input is interpolated directly into the expression string, an attacker can inject XPath operators to alter query logic. Unlike SQL databases, XML documents have no per-element access control: a single injected expression can traverse the entire document tree and return arbitrary nodes.

Authentication bypass is a common consequence. A filter such as `//user[name='INPUT' and password='INPUT']` can be bypassed by supplying `' or '1'='1` as the username, turning the expression into `//user[name='' or '1'='1' and password='...']`, which selects all user nodes. From this foothold, more targeted payloads can exfiltrate every value in the document — configuration data, secrets stored as XML, or PII.

XPath injection is not as widely known as SQL injection, which means it is more likely to appear in code review blind spots and static analysis exclusion lists. Because Java's `javax.xml.xpath` API lacks native parameterization, the fix requires a deliberate design choice rather than a simple API swap.

## What Gets Flagged

The rule matches `.java` files where `xpath.evaluate()` or `xpath.compile()` is called with either a request parameter as an argument, or with a `+` concatenation in the expression string.

```java
// FLAGGED: user input passed directly to evaluate()
String username = request.getParameter("user");
String result = xpath.evaluate(
    "//users/user[name='" + username + "']",
    doc);

// FLAGGED: compile() with concatenation
String filter = request.getParameter("filter");
XPathExpression expr = xpath.compile("/catalog/item[" + filter + "]");
NodeList items = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);

// FLAGGED: evaluate with request parameter reference on same line
xpath.evaluate("//accounts/account[id='" + request.getParameter("id") + "']",
    doc, XPathConstants.STRING);
```

## Remediation

Java's `javax.xml.xpath` API does not natively support parameterized queries in the same way JDBC's `PreparedStatement` does, but the `XPathVariableResolver` interface provides an equivalent mechanism: user-supplied values are bound as typed variables, never interpolated as expression syntax.

1. **Use `XPathVariableResolver` for parameterized XPath queries:**

   ```java
   // SAFE: user value is bound as a typed variable, not expression syntax
   import javax.xml.namespace.QName;
   import javax.xml.xpath.*;

   String username = request.getParameter("user");

   XPathFactory factory = XPathFactory.newInstance();
   XPath xpath = factory.newXPath();

   // Bind user input as a variable — it cannot alter expression structure
   xpath.setXPathVariableResolver(variableName -> {
       if ("username".equals(variableName.getLocalPart())) {
           return username;
       }
       return null;
   });

   // Expression uses $username; structure is fixed at compile time
   XPathExpression expr = xpath.compile("//users/user[name=$username]");
   NodeList nodes = (NodeList) expr.evaluate(doc, XPathConstants.NODESET);
   ```

   The variable resolver passes the user value as a data binding. The XPath engine never interprets it as part of the expression syntax, so injection metacharacters such as `'`, `"`, `[`, `]`, `or`, and `and` are treated as literal string data.

2. **Validate input against a strict allowlist before any XPath use.** Even with variable resolvers, apply upfront validation to reject values that do not conform to the expected format. For numeric identifiers, parse as an integer. For names, enforce an alphanumeric pattern:

   ```java
   // Supplementary guard: allowlist validation before XPath
   String username = request.getParameter("user");
   if (username == null || !username.matches("[a-zA-Z0-9._@-]{1,64}")) {
       response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid username");
       return;
   }
   // Proceed with variable resolver pattern above
   ```

3. **Pre-compile expressions outside of request handlers.** Compile XPath expressions once at startup (e.g. in a `@PostConstruct` method or Spring bean initializer) and cache the resulting `XPathExpression`. This eliminates any possibility of per-request expression construction and improves performance:

   ```java
   @Component
   public class UserXPathQueries {
       private final XPathExpression findByName;

       @PostConstruct
       public void init() throws XPathExpressionException {
           XPath xpath = XPathFactory.newInstance().newXPath();
           // Expression is fixed — user values will be bound via variable resolver
           this.findByName = xpath.compile("//users/user[name=$username]");
       }

       public NodeList findUser(Document doc, String username)
               throws XPathExpressionException {
           XPath xpath = XPathFactory.newInstance().newXPath();
           xpath.setXPathVariableResolver(name ->
               "username".equals(name.getLocalPart()) ? username : null);
           return (NodeList) findByName.evaluate(doc, XPathConstants.NODESET);
       }
   }
   ```

4. **Consider replacing XML with a database or JSON store.** If XPath queries are used to implement business logic that grows complex over time, the design may benefit from migrating to a relational or document database that provides native parameterized query APIs with access control semantics.

5. **Apply least-privilege document access.** If the XML document contains mixed-sensitivity data, consider splitting it into separately loaded documents so that a given handler only receives the subset of the tree relevant to its function. An injected query can only reach data present in the `Document` object passed to `evaluate()`.

## References

- [CWE-643: Improper Neutralization of Data within XPath Expressions](https://cwe.mitre.org/data/definitions/643.html)
- [CAPEC-83: XPath Injection](https://capec.mitre.org/data/definitions/83.html)
- [MITRE ATT&CK T1190 – Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [SEI CERT IDS53-J: Prevent XPath Injection](https://wiki.sei.cmu.edu/confluence/display/java/IDS53-J.+Prevent+XPath+Injection)
- [OWASP XPath Injection](https://owasp.org/www-community/attacks/XPATH_Injection)
- [OWASP Injection Prevention in Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_in_Java_Cheat_Sheet.html)
- [OWASP ASVS V5.2 – Sanitization and Sandboxing](https://owasp.org/www-project-application-security-verification-standard/)
- [Java javax.xml.xpath API documentation](https://docs.oracle.com/en/java/javase/21/docs/api/java.xml/javax/xml/xpath/package-summary.html)
