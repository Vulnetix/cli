---
title: "VNX-JAVA-011 – Java Expression Language Injection"
description: "Detects use of SpEL, OGNL, and ScriptEngine to evaluate user-controlled input as expressions, enabling remote code execution through expression language sandbox bypass."
---

## Overview

This rule detects instantiation and use of Spring Expression Language (SpEL) via `SpelExpressionParser`, OGNL evaluation via `OgnlUtil` or `Ognl.getValue`, and generic scripting engines via `ScriptEngineManager` or `ScriptEngine.eval()`, particularly when the expression string is derived from request parameters. Evaluating attacker-controlled data as a programming expression grants the same capabilities as direct code execution. This is CWE-917 (Improper Neutralization of Special Elements used in an Expression Language Statement).

**Severity:** Critical | **CWE:** [CWE-917 – Improper Neutralization of Special Elements used in an Expression Language Statement (EL Injection)](https://cwe.mitre.org/data/definitions/917.html)

## Why This Matters

Expression language engines are designed to be powerful. SpEL can call arbitrary Java methods on any object in the evaluation context, including `Runtime.exec()`, `ProcessBuilder`, and reflection-based class loading. An attacker who can control the expression string can execute OS commands, read and write files, exfiltrate environment variables, and load remote classes into the JVM — all without any exploit primitive beyond the ability to submit a string.

SpEL injection has been demonstrated in high-profile CVEs: CVE-2022-22963 (Spring Cloud Function, CVSS 9.8) allowed unauthenticated RCE by sending a SpEL expression in the `spring.cloud.function.routing-expression` HTTP header. CVE-2018-1273 (Spring Data Commons) exploited SpEL evaluation of user-supplied property paths in Spring Data REST. OGNL injection is the mechanism behind the long series of Apache Struts RCE vulnerabilities including CVE-2017-5638 (S2-045, the Equifax breach vector).

## What Gets Flagged

The rule matches any `.java` file containing indicators of expression evaluation, particularly when combined with request parameter reads.

```java
// FLAGGED: SpEL parser with user input as the expression
String expr = request.getParameter("filter");
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression(expr);  // RCE if expr is attacker-controlled
Object result = exp.getValue(context);

// FLAGGED: OGNL evaluation
String ognlExpr = request.getParameter("template");
Object value = Ognl.getValue(ognlExpr, context, root);

// FLAGGED: ScriptEngine with user-controlled script
ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
engine.eval(request.getParameter("script"));  // full JS engine, can call Java

// FLAGGED: JSR-245 Expression Factory
ExpressionFactory ef = ExpressionFactory.newInstance();
ef.createValueExpression(elContext, request.getParameter("el"), Object.class);
```

## Remediation

1. **Never evaluate user input as an expression.** This is the primary and most important recommendation. If you need to implement dynamic filtering, sorting, or templating based on user preferences, use a whitelist of pre-compiled expressions, not runtime evaluation of user-supplied strings.

2. **Use `SimpleEvaluationContext` when SpEL evaluation of data is genuinely needed.** `SimpleEvaluationContext` provides a restricted evaluation environment that exposes only property access and configured operators — it does not allow method invocations, type references, or constructor calls. Use it instead of `StandardEvaluationContext` for any expression derived from external input.

   ```java
   // SAFER: SimpleEvaluationContext limits what SpEL can do
   // Still — do not use user input as the expression. Use it only for
   // expressions you control, against data objects the user provides.
   ExpressionParser parser = new SpelExpressionParser();
   Expression expression = parser.parseExpression("firstName + ' ' + lastName");

   SimpleEvaluationContext context = SimpleEvaluationContext
       .forReadOnlyDataBinding()
       .withRootObject(userSuppliedData)  // data from user, not the expression
       .build();

   String result = expression.getValue(context, String.class);
   ```

3. **For dynamic filtering or querying, use a purpose-built safe API.** Spring Data's `Specification` API, QueryDSL predicates, or RSQL parsers provide safe, typed query construction that cannot execute arbitrary code.

   ```java
   // SAFE: QueryDSL predicate — user controls values, not code
   QProduct product = QProduct.product;
   BooleanExpression predicate = product.category.eq(request.getParameter("category"))
       .and(product.price.lt(new BigDecimal(request.getParameter("maxPrice"))));
   productRepository.findAll(predicate);
   ```

4. **Disable or sandbox `ScriptEngine` use entirely.** If you need server-side scripting by end users, use a purpose-built sandboxed interpreter (such as GraalVM's Polyglot sandbox with resource limits, or a separate isolated process with no filesystem or network access). Standard `javax.script` engines run in the same JVM with full permissions.

5. **Audit all uses of `@Value` annotations with SpEL.** Spring's `@Value("#{...}")` annotations support SpEL. Ensure no `@Value` expression includes a property sourced from external, user-controllable configuration. Prefer `@Value("${property.name}")` (property placeholder, not expression) for simple value injection.

## References

- [CWE-917: Improper Neutralization of Special Elements used in an Expression Language Statement](https://cwe.mitre.org/data/definitions/917.html)
- [CAPEC-242: Code Injection](https://capec.mitre.org/data/definitions/242.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [CVE-2022-22963 – Spring Cloud Function SpEL Injection](https://spring.io/security/cve-2022-22963)
- [CVE-2018-1273 – Spring Data Commons SpEL Injection](https://pivotal.io/security/cve-2018-1273)
- [Spring Framework – SimpleEvaluationContext](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/expression/spel/support/SimpleEvaluationContext.html)
- [OWASP Expression Language Injection](https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection)
- [OWASP ASVS V5 – Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
