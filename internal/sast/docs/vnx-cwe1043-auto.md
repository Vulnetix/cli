---
title: "VNX-1043 – Data Element Aggregating an Excessively Large Number of Non-Primitive Elements"
description: "Reports a Java class, Go struct, Python class or TypeScript class/interface that declares more than 10 instance fields of non-primitive type, on its declaration line."
---

## Overview

VNX-1043 applies the CISQ maintainability measure behind [CWE-1043](https://cwe.mitre.org/data/definitions/1043.html): a data element that aggregates too many other objects. It counts the instance fields declared directly in the body of each type and reports the declaration when more than 10 of them are of a non-primitive type.

What is counted:

- **Java**: instance fields of a `class` (not `static` fields, constants or records).
- **Go**: fields of a `struct` type, including grouped names (`a, b *T`) and embedded types.
- **Python**: annotated class-level fields (dataclasses, pydantic, attrs or any class), not `ClassVar`.
- **TypeScript**: fields of a `class`, an `interface` or an object `type` alias.

A field is non-primitive when its type names anything other than a primitive or value type: numbers, booleans, strings, bytes, dates, times, durations, UUIDs, `BigDecimal`, the boxed types, `error` and `any`/`unknown`. So `List<Order>`, `map[string]*Session`, `Optional[Cart]` and `Role[]` count, while `List<String>`, `[]byte`, `dict[str, str]` and `'light' | 'dark'` do not.

Not reported: fields of a nested class (they count toward the nested class), method parameters, enums, plain JavaScript, generated code (`Code generated ... DO NOT EDIT`, `@Generated`), test code and comments. CISQ suggests 5 as the threshold; this rule uses 10 so that it reports only the outliers.

**Severity:** Low | **CWE:** [CWE-1043](https://cwe.mitre.org/data/definitions/1043.html)

## Why This Matters

An object that holds a dozen other objects is hard to review. Each one is something it might serialise into a response, write to a log, keep alive in a cache or hand to another component. When a type grows to that size, nobody checks every field before the type is returned from an API, and data that was never meant to leave the server leaves with it.

## What Gets Flagged

```java
public class OrderContext {                 // FLAGGED: 12 non-primitive fields
    private final Customer customer;
    private Address billingAddress;
    private List<OrderLine> lines;
    private Map<String, Discount> discounts;
    // ... eight more object fields
}
```

```go
type Server struct {                         // FLAGGED
	cfg      *Config
	sessions map[string]*Session
	inbound, outbound chan *Message
	*Logger
	// ...
}
```

## What Is Not Flagged

```java
public class Customer {
    private Long id;
    private String email;        // strings, boxed numbers and dates are primitive here
    private Address address;
}
```

## Remediation

1. Group related fields into their own types (an `Addresses` value with billing and shipping, a `Payment` with method and invoice).
2. Keep request-scoped context separate from long-lived dependencies.
3. Return purpose-built response types from APIs instead of the aggregate itself.

## References

- [CWE-1043: Data Element Aggregating an Excessively Large Number of Non-Primitive Elements](https://cwe.mitre.org/data/definitions/1043.html)
- [CISQ Automated Source Code Maintainability Measure](https://www.it-cisq.org/standards/code-quality-standards/)
