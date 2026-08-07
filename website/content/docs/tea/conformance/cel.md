---
title: CEL
weight: 7
description: "the query language, cross-checked against the reference CEL implementation"
---


the query language, cross-checked against the reference CEL implementation

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 16 | 16 | 0 | 0 |

## Query language

Every expression below was compiled twice: once by `google/cel-go`, which is the
reference implementation, and once by this server. The finding is the disagreement,
not either result on its own. A server with its own parser can accept an expression
CEL rejects, and a client generated from the specification would then write queries
that quietly do not mean what its author thought.

| Measure | Value |
|---|---:|
| Expressions checked | 15 |
| Server agrees with the reference implementation | 15 |
| Disagreements | 0 |

### cel cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| the always-true selector | `postStaticInsights` | 200 | - | 2257.79 ms | pass |
| equality on a scalar field | `postStaticInsights` | 200 | - | 113.89 ms | pass |
| conjunction of two predicates | `postStaticInsights` | 200 | - | 29.89 ms | pass |
| a macro over a list field | `postStaticInsights` | 200 | - | 515.33 ms | pass |
| membership with the in operator | `postStaticInsights` | 200 | - | 32.71 ms | pass |
| membership with contains() | `postStaticInsights` | 200 | - | 112.65 ms | pass |
| null comparison | `postStaticInsights` | 200 | - | 111.08 ms | pass |
| disjunction with grouping | `postStaticInsights` | 200 | - | 1858.68 ms | pass |
| negation | `postStaticInsights` | 200 | - | 2257.83 ms | pass |
| a ternary | `postStaticInsights` | 200 | - | 964.65 ms | pass |
| an unterminated comparison | `postStaticInsights` | 400 | - | 33.97 ms | pass |
| an expression that is not a predicate | `postStaticInsights` | 400 | - | 111.00 ms | pass |
| an unbalanced parenthesis | `postStaticInsights` | 400 | - | 32.60 ms | pass |
| an assignment | `postStaticInsights` | 400 | - | 112.60 ms | pass |
| a SQL fragment | `postStaticInsights` | 400 | - | 32.63 ms | pass |
| an empty expression | `postStaticInsights` | 400 | - | 25.72 ms | pass |


[Back to the summary](../)
