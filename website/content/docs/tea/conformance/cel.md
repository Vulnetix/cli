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
| the always-true selector | `postStaticInsights` | 200 | - | 1692.56 ms | pass |
| equality on a scalar field | `postStaticInsights` | 200 | - | 47.54 ms | pass |
| conjunction of two predicates | `postStaticInsights` | 200 | - | 30.40 ms | pass |
| a macro over a list field | `postStaticInsights` | 200 | - | 650.63 ms | pass |
| membership with the in operator | `postStaticInsights` | 200 | - | 26.85 ms | pass |
| membership with contains() | `postStaticInsights` | 200 | - | 28.59 ms | pass |
| null comparison | `postStaticInsights` | 200 | - | 146.18 ms | pass |
| disjunction with grouping | `postStaticInsights` | 200 | - | 1579.16 ms | pass |
| negation | `postStaticInsights` | 200 | - | 1692.57 ms | pass |
| a ternary | `postStaticInsights` | 200 | - | 1828.84 ms | pass |
| an unterminated comparison | `postStaticInsights` | 400 | - | 137.76 ms | pass |
| an expression that is not a predicate | `postStaticInsights` | 400 | - | 47.49 ms | pass |
| an unbalanced parenthesis | `postStaticInsights` | 400 | - | 47.49 ms | pass |
| an assignment | `postStaticInsights` | 400 | - | 47.45 ms | pass |
| a SQL fragment | `postStaticInsights` | 400 | - | 47.47 ms | pass |
| an empty expression | `postStaticInsights` | 400 | - | 18.75 ms | pass |


[Back to the summary](../)
