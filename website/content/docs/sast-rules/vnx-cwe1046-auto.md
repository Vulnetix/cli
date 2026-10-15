---
title: "VNX-1046 – Creation of Immutable Text Using String Concatenation"
description: "Reports a Java or C# String accumulated with +=, s = s + ... or s = s.concat(...) inside a for, foreach, while or do loop, where the variable is a String local declared before the loop."
---

## Overview

VNX-1046 reports [CWE-1046: Creation of Immutable Text Using String Concatenation](https://cwe.mitre.org/data/definitions/1046.html) in Java and C#. The finding is an `s += ...`, `s = s + ...` or Java `s = s.concat(...)` statement inside the body of a `for`, `foreach`, `while` or `do` loop, where `s` is a local declared as `String`/`string` (or a C# `var` initialised with a string literal or `string.Empty`) before the loop. Braced bodies, Allman-style braces, a single unbraced statement and a statement on the loop's own line are all covered.

Not reported: `StringBuilder`, `StringBuffer` and `StringJoiner` appends, `String.join` and `Collectors.joining`, concatenation after the loop ends, numeric `+=` on `int`/`long`/`double` variables (including a name that an earlier method declared as a String), a String declared inside the loop body (rebuilt each iteration rather than accumulated), fields and variables declared more than 100 lines above, Kotlin and other JVM languages, test code, comments and strings.

**Severity:** Low | **CWE:** [CWE-1046](https://cwe.mitre.org/data/definitions/1046.html)

## Why This Matters

Strings in Java and C# are immutable. Every `+=` allocates a new string and copies the whole text built so far into it, so building a string of n pieces in a loop costs time proportional to n squared. When the loop count comes from a request (rows returned, items posted, lines uploaded), the request controls how much CPU the server spends. Every intermediate copy also stays on the heap until it is collected. When the text is a password, a token or key material, that leaves many copies of the secret in memory, where a heap dump or a memory-disclosure bug can find them.

## What Gets Flagged

```java
String csv = "";
for (Column column : columns) {
    csv += column.getName() + ",";            // FLAGGED
}
```

```java
String hex = "";
for (byte b : digest) hex += String.format("%02x", b);   // FLAGGED
```

```csharp
string list = "";
foreach (var id in ids)
{
    list += id + ",";                          // FLAGGED
}
```

## What Is Not Flagged

```java
StringBuilder csv = new StringBuilder();
for (Column column : columns) {
    csv.append(column.getName()).append(',');
}

for (Order order : orders) {
    String line = order.getId() + ": ";        // a new String each iteration
    line += order.getAmount();
}
```

## Remediation

1. Accumulate into a `StringBuilder` (Java and C#) and call `toString()`/`ToString()` once.
2. Use `String.join`, `Collectors.joining` or `string.Join` when joining a collection.
3. For secrets, use a `char[]` or `byte[]` buffer that you can overwrite when done, not a String.

## References

- [CWE-1046: Creation of Immutable Text Using String Concatenation](https://cwe.mitre.org/data/definitions/1046.html)
- [Java SE: StringBuilder](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/StringBuilder.html)
- [.NET: StringBuilder](https://learn.microsoft.com/en-us/dotnet/api/system.text.stringbuilder)
