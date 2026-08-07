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
| the Insights API is reachable and answers a static query | `postStaticInsights` | 200 | - | 6686.86 ms | pass |
| select every component | `postStaticInsights` | 200 | - | 778.71 ms | pass |
| third-party components of a product | `postStaticInsights` | 200 | - | 1624.84 ms | pass |
| open-source components of a product | `postStaticInsights` | 200 | - | 1518.55 ms | pass |
| components with any vulnerability | `postStaticInsights` | 200 | - | 1616.32 ms | pass |
| cryptographic assets | `postStaticInsights` | 200 | - | 458.75 ms | pass |
| AI components | `postStaticInsights` | 200 | - | 229.29 ms | pass |
| components with an OpenSSF Scorecard | `postStaticInsights` | 200 | - | 1722.85 ms | pass |
| components with build provenance | `postStaticInsights` | 200 | - | 119.95 ms | pass |
| reject an invalid CEL expression | `postStaticInsights` | 400 | - | 28.86 ms | pass |
| reject a non-boolean expression | `postStaticInsights` | 400 | - | 119.94 ms | pass |
| reject a missing expression | `postStaticInsights` | 400 | - | 119.92 ms | pass |
| reject a malformed body | `postStaticInsights` | 400 | - | 52.62 ms | pass |
| unauthenticated request is rejected | `postStaticInsights` | 401 | - | 30.21 ms | pass |
| defaults to the specification's CycloneDX 1.6 | `postStaticInsights` | 200 | - | 3583.82 ms | pass |
| negotiates CycloneDX 1.7 on request | `postStaticInsights` | 200 | - | 3630.34 ms | pass |
| natural-language query | `postDynamicInsights` | 503 | - | 1624.80 ms | pass |
| reject a missing prompt | `postDynamicInsights` | 400 | - | 52.63 ms | pass |
| find a component by name | `postStaticInsights` | 200 | - | 52.72 ms | pass |
| find a component by vulnerability identifier | `postStaticInsights` | 200 | - | 2239.49 ms | pass |
| find a component by vulnerability identifier using in | `postStaticInsights` | 200 | - | 52.74 ms | pass |


[Back to the summary](../)
