---
title: "VNX-JAVA-005 – Insecure Deserialization"
description: "Detects use of ObjectInputStream.readObject(), XMLDecoder, XStream, and Jackson default typing, all of which can execute arbitrary code when deserializing attacker-controlled data via gadget chains."
---

## Overview

This rule detects indicators of Java object deserialization without allowlisting — specifically `ObjectInputStream`, `readObject()`, `readUnshared()`, `XMLDecoder`, `XStream`, `enableDefaultTyping()`, and `activateDefaultTyping()`. Deserializing untrusted byte streams through any of these mechanisms can trigger arbitrary code execution via gadget chains: sequences of legitimate library classes whose deserialization callbacks can be chained together to achieve effects such as command execution, class loading from remote URLs, or file system access. This is CWE-502.

**Severity:** Critical | **CWE:** [CWE-502 – Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

## Why This Matters

Java's native serialization protocol (`aced 0005` magic bytes) is a remote code execution primitive when common libraries are on the classpath. The 2015 Apache Commons Collections exploit demonstrated that any application using `ObjectInputStream.readObject()` on attacker data while having Commons Collections on the classpath was trivially exploitable — regardless of what the application thought it was deserializing. Similar gadget chains exist for Spring, Hibernate, Groovy, and many other ubiquitous libraries.

The impact is typically unauthenticated remote code execution with the JVM's OS-level privileges. High-profile real-world exploits include the 2017 WebLogic mass exploitation events (CVE-2017-3248, CVE-2019-2725), the JBoss/Jenkins gadget chain exploits, and the continuous stream of Jackson polymorphic deserialization CVEs. The same class of vulnerability underpins the Log4Shell exploit chain, which used JNDI lookups initiated during deserialization.

## What Gets Flagged

The rule matches any `.java` file containing one of the high-risk identifiers.

```java
// FLAGGED: ObjectInputStream without filter
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // gadget chain execution possible

// FLAGGED: XMLDecoder deserializes arbitrary Java objects
XMLDecoder decoder = new XMLDecoder(request.getInputStream());
Object result = decoder.readObject();

// FLAGGED: XStream without security configuration
XStream xstream = new XStream();
Object data = xstream.fromXML(request.getReader());

// FLAGGED: Jackson with dangerous default typing
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // deprecated, known-vulnerable
```

## Remediation

1. **Apply a Java serialization filter (`ObjectInputFilter`).** Introduced in Java 9 and backported to Java 8u121, `ObjectInputFilter` lets you implement an allowlist of classes that may be deserialized. The JVM rejects any class not on the list before its constructor runs, breaking gadget chains.

   ```java
   // SAFE: allowlist-based ObjectInputFilter
   ObjectInputStream ois = new ObjectInputStream(inputStream);
   ois.setObjectInputFilter(filterInfo -> {
       Class<?> cls = filterInfo.serialClass();
       if (cls == null) return ObjectInputFilter.Status.UNDECIDED;
       if (cls == MyTransferObject.class || cls == AnotherSafeClass.class) {
           return ObjectInputFilter.Status.ALLOWED;
       }
       return ObjectInputFilter.Status.REJECTED;
   });
   MyTransferObject obj = (MyTransferObject) ois.readObject();
   ```

2. **Configure a JVM-wide serialization filter.** Set the `jdk.serialFilter` system property or `$JAVA_HOME/conf/security/java.security` to apply a global allowlist to all `ObjectInputStream` instances in the application:

   ```
   # java.security or -Djdk.serialFilter=
   jdk.serialFilter=com.example.MyTransferObject;!*
   ```

3. **Replace native serialization with a data-only format.** JSON (Jackson with `FAIL_ON_UNKNOWN_PROPERTIES` enabled and default typing disabled), Protocol Buffers, or Avro transmit data without triggering arbitrary class constructors. This is the most robust long-term fix.

   ```java
   // SAFE: Jackson without polymorphic default typing
   ObjectMapper mapper = new ObjectMapper();
   mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
   // Do NOT call enableDefaultTyping() or activateDefaultTyping()
   MyDto dto = mapper.readValue(json, MyDto.class);
   ```

4. **Configure XStream with a security framework.** If you must use XStream, call `xstream.allowTypes()` or use `XStream.setupDefaultSecurity(xstream)` followed by an explicit allowlist before processing any external input.

5. **Use the serialization kill-switch.** On Java 8u261+ you can set `-Djdk.disableLastUsageTracking` and rely on the JVM's built-in filter; alternatively, add `NotSerializableExceptionMapping` wrappers around untrusted data entry points.

6. **Deploy the OWASP Java Serialization Security library or SerialKiller** as a drop-in `ObjectInputStream` replacement for legacy code you cannot refactor immediately.

7. **Monitor for the `aced 0005` magic bytes** at WAF and network layer. Blocking raw Java serialization payloads at the perimeter provides defence-in-depth while code is being remediated.

## References

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [CAPEC-586: Object Injection](https://capec.mitre.org/data/definitions/586.html)
- [MITRE ATT&CK T1059 – Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [JEP 290 – Filter Incoming Serialization Data](https://openjdk.org/jeps/290)
- [NVD CVE-2015-7501 – Commons Collections gadget chain](https://nvd.nist.gov/vuln/detail/CVE-2015-7501)
- [OWASP Top 10 A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [OWASP ASVS V5 – Validation, Sanitization and Encoding](https://owasp.org/www-project-application-security-verification-standard/)
