---
title: "VNX-JAVA-030 – Java Reflected Cross-Site Scripting"
description: "Reports Java code that writes servlet request data into an HTML response without output encoding: response.getWriter() and PrintWriter/JspWriter/ServletOutputStream writes, JSP scriptlet expressions and out.print, and values returned from Spring methods that produce text/html, unless the value passed through an HTML encoder, was parsed to a number, folded to a constant, or the response is not HTML."
---

## Overview

This rule detects Java code that sends HTTP request data back to the browser inside an HTML response without encoding it. The value can come straight from `request.getParameter()`, `getHeader()`, `getCookies()`, `getQueryString()`, `getPathInfo()` or `getRequestURI()`, from an annotated Spring or JAX-RS handler parameter (`@RequestParam`, `@PathVariable`, `@RequestBody`), or from a local assigned from one of those. An attacker who gets a victim to follow a crafted link makes the page run the attacker's script in the victim's session. This is reflected cross-site scripting, CWE-79.

**Severity:** High | **CWE:** [CWE-79 – Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

## Why This Matters

Script that runs in the origin of your application can read anything the user can read and do anything the user can do: it can steal session tokens that are not `HttpOnly`, submit forms, change the account email, or rewrite the page to harvest credentials. A reflected value needs no stored data, only a link, so it spreads by email, chat and search results.

Output encoding is the control that works, because it is applied at the one place the context is known. Input validation helps but cannot stand in for it: a name such as `O'Brien` is valid input and still breaks out of a single-quoted attribute.

## What Gets Flagged

The rule reports the response write whose argument carries request data:

- `response.getWriter()` followed by `print`, `println`, `write`, `printf`, `format` or `append`, including a call split across lines;
- the same methods on a local assigned from `getWriter()` or `getOutputStream()`, and on a `PrintWriter`, `JspWriter` or `ServletOutputStream` parameter;
- `response.getOutputStream().write(...)`;
- a JSP scriptlet expression `<%= ... %>` and `out.print`/`out.println` in a `.jsp` file;
- a `return` of a Spring `@ResponseBody` or `@RestController` method, or a `ResponseEntity` body, whose mapping produces `text/html` (`produces = "text/html"`, `MediaType.TEXT_HTML`).

The value is followed up to ten assignments back inside the enclosing method (at most 120 lines up), through lists, maps and builders, through a for-each over `request.getCookies()`, and across statements that span several lines.

```java
// FLAGGED: request value concatenated into the page
String name = request.getParameter("name");
response.getWriter().println("<p>Hello " + name + "</p>");

// FLAGGED: through a writer local and a cookie
PrintWriter out = response.getWriter();
for (Cookie c : request.getCookies()) {
    if (c.getName().equals("theme")) theme = c.getValue();
}
out.print("<body class='" + theme + "'>");

// FLAGGED: the list element is the header value
items.add("bread");
items.add(request.getHeader("X-Extra"));
String last = items.get(1);
response.getWriter().println("<li>" + last + "</li>");

// FLAGGED: Spring method that produces HTML
@GetMapping(value = "/greet", produces = "text/html")
@ResponseBody
public String greet(@RequestParam String name) {
    return "<h1>Hello " + name + "</h1>";
}
```

```jsp
<%-- FLAGGED --%>
<p>You searched for: <%= request.getParameter("q") %></p>
```

### Helpers in other files

A call into another class of the project is read from that class's own source instead of being guessed at. For `obj.m(args)`, `Cls.m(args)` and `new Cls(args).m(args)` the class is found by the declared type of `obj` (a local, a parameter, or the `new Cls(...)` it was assigned from) or by the static class name, and the method (at most 60 lines, overloads told apart by arity) is summarised as one of:

- **constant**: every return is a literal, an `UPPER_CASE` name, a field initialised to a literal and never assigned again, or the result of a constant method of the same class. The call is as constant as that literal, whatever it is handed.
- **a function of its arguments**: every return is constant once the parameters, and the fields the class's one constructor stores from its own parameters, are taken as constants. The call is only as risky as the arguments it depends on: a getter of a value stored by `new Cls(arg)` is as tainted as `arg`, and a method that ignores one of its parameters is not tainted by it.
- **opaque**: anything else, such as a method that reads a request value or a header, a field a setter can change, or a call the summary cannot see through.

A value of an interface or base class type runs the method of every project class that extends or implements it, so one implementation that returns its parameter keeps the call as tainted as that parameter. What is still reported: opaque calls, a simple class name that two files declare (ambiguous), a class outside the project, a type with an anonymous subclass, and a callee that hands the value to a third class (a callee is read one level deep). A method of the same file called without a receiver is summarised the same way.

```java
// NOT FLAGGED: Sanitizer.clean ignores its argument and returns a literal
String value = sanitizer.clean(request.getParameter("value"));
response.getWriter().println("<p>" + value + "</p>");

// NOT FLAGGED: the constructor argument is a literal, so the getter is too
Holder holder = new Holder("report");
response.getWriter().println("<p>" + holder.get() + "</p>");

// FLAGGED: Echo.same returns its argument
String value = echo.same(request.getParameter("value"));
response.getWriter().println("<p>" + value + "</p>");

// FLAGGED: the getter returns what the constructor was given
Holder holder = new Holder(request.getParameter("value"));
response.getWriter().println("<p>" + holder.get() + "</p>");
```

### What is not flagged

- A value passed through an HTML, attribute or script encoder: ESAPI `encodeForHTML`, `encodeForHTMLAttribute`, `encodeForJavaScript`; OWASP Encoder `Encode.forHtml*` and `Encode.forJavaScript*`; Apache Commons `StringEscapeUtils.escapeHtml3/4` and `escapeXml*`; Spring `HtmlUtils.htmlEscape`; `Jsoup.clean`; any `escape*` or `sanitize*` call.
- A same-file method that calls one of those encoders, so a wrapper such as `String shown = clean(name)` counts as encoding.
- A name whose latest unconditional assignment was an encoder call (`name = HtmlUtils.htmlEscape(name)`). An encoding inside an `if` that is not taken on every path does not count.
- A number or boolean parsed from the value (`Integer.parseInt`, `Long.parseLong`, `Boolean.parseBoolean`) and annotated numeric parameters.
- A value that provably holds a constant at the write: a branch a constant condition never takes, a list element or map key that holds a literal, or the result of a same-file method whose every return is constant.
- A response whose content type was set to something other than HTML before the write (`application/json`, `text/plain`, `text/csv`, `MediaType.APPLICATION_JSON`, `produces = "application/json"`), and Spring methods that do not declare `text/html`.
- Sink names inside comments and string literals, writers that are not the response (`new PrintWriter(file)`, `FileWriter`), and test sources.

```java
// NOT FLAGGED: encoded at the point of output
response.getWriter().println("<p>" + Encode.forHtml(name) + "</p>");

// NOT FLAGGED: JSON is not interpreted as HTML
response.setContentType("application/json");
response.getWriter().write("{\"id\": \"" + id + "\"}");

// NOT FLAGGED: a number cannot carry markup
int page = Integer.parseInt(request.getParameter("page"));
response.getWriter().println("<p>Page " + page + "</p>");
```

Flows into another file, and into another method other than a same-file encoder or a method returning a constant, are not followed. A servlet that never calls `setContentType` is treated as HTML, which is the default for a writer.

## Remediation

1. **Encode for the context at the point of output.** Use the encoder that matches where the value lands: HTML body, attribute value, JavaScript string, URL or CSS.

   ```java
   // SAFE: OWASP Java Encoder
   response.getWriter().println("<p>Hello " + Encode.forHtml(name) + "</p>");
   response.getWriter().println("<a title='" + Encode.forHtmlAttribute(name) + "'>x</a>");
   response.getWriter().println("<script>var n = '" + Encode.forJavaScript(name) + "';</script>");
   ```

2. **Use a template engine that escapes by default** (Thymeleaf `th:text`, JSP with `<c:out>` or `fn:escapeXml`, Freemarker auto-escaping) instead of building HTML by hand.

   ```jsp
   <%-- SAFE --%>
   <p>You searched for: <c:out value="${param.q}"/></p>
   ```

3. **Return data, not markup.** For APIs set `application/json` and let the client build the page with `textContent`. In Spring, return a view name or a JSON object instead of an HTML string.

4. **Parse values that must be numbers** (`Integer.parseInt`) and reject anything else with a 400 response.

5. **Add defence in depth.** A Content-Security-Policy without `unsafe-inline`, `HttpOnly` and `SameSite` cookies reduce the impact of a missed encoder; they do not replace it.

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [CAPEC-63: Cross-Site Scripting (XSS)](https://capec.mitre.org/data/definitions/63.html)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP Java Encoder Project](https://owasp.org/www-project-java-encoder/)
- [OWASP Top 10 A03:2021 – Injection](https://owasp.org/Top10/A03_2021-Injection/)
