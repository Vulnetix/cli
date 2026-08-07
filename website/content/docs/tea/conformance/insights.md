---
title: Insights
weight: 6
description: "the Insights API and the CycloneDX documents it answers with"
---


the Insights API and the CycloneDX documents it answers with

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 21 | 21 | 0 | 0 |

## Insights API

A separate specification mounted at `https://www.vulnetix.com/insights`. Its responses are CycloneDX documents, so
they are validated against the CycloneDX schema and not against anything in the
Insights document. That is where its `$ref` points, and it is where conformance
actually lives.

| Measure | Value |
|---|---|
| Insights specification | 1.0.0 |
| Component found for the efficacy queries | actions/checkout |
| Vulnerability found for the efficacy queries | "ALAS-2015-512" |
| Dynamic endpoint | no inference backend is configured on this deployment |

### insights cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| the Insights API is reachable and answers a static query | `postStaticInsights` | 200 | - | 638.69 ms | pass |
| select every component | `postStaticInsights` | 200 | - | 2113.35 ms | pass |
| third-party components of a product | `postStaticInsights` | 200 | - | 32.37 ms | pass |
| open-source components of a product | `postStaticInsights` | 200 | - | 32.34 ms | pass |
| components with any vulnerability | `postStaticInsights` | 200 | - | 33.52 ms | pass |
| cryptographic assets | `postStaticInsights` | 200 | - | 241.28 ms | pass |
| AI components | `postStaticInsights` | 200 | - | 61.97 ms | pass |
| components with an OpenSSF Scorecard | `postStaticInsights` | 200 | - | 241.26 ms | pass |
| components with build provenance | `postStaticInsights` | 200 | - | 29.82 ms | pass |
| reject an invalid CEL expression | `postStaticInsights` | 400 | - | 218.84 ms | pass |
| reject a non-boolean expression | `postStaticInsights` | 400 | - | 25.56 ms | pass |
| reject a missing expression | `postStaticInsights` | 400 | - | 318.00 ms | pass |
| reject a malformed body | `postStaticInsights` | 400 | - | 25.54 ms | pass |
| unauthenticated request is rejected | `postStaticInsights` | 401 | - | 25.46 ms | pass |
| defaults to the specification's CycloneDX 1.6 | `postStaticInsights` | 200 | - | 2113.92 ms | pass |
| negotiates CycloneDX 1.7 on request | `postStaticInsights` | 200 | - | 1742.40 ms | pass |
| natural-language query | `postDynamicInsights` | 503 | - | 31.25 ms | pass |
| reject a missing prompt | `postDynamicInsights` | 400 | - | 89.78 ms | pass |
| find a component by name | `postStaticInsights` | 200 | - | 59.05 ms | pass |
| find a component by vulnerability identifier | `postStaticInsights` | 200 | - | 61.84 ms | pass |
| find a component by vulnerability identifier using in | `postStaticInsights` | 200 | - | 29.89 ms | pass |


[Back to the summary](../)
