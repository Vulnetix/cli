---
title: purl
weight: 3
description: "package-URL identifiers, filters and purl-typed TEIs"
---


package-URL identifiers, filters and purl-typed TEIs

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 7 | 7 | 0 | 0 |

## Package URLs

| Measure | Value |
|---|---:|
| Published purl identifiers | 42 |
| Malformed | 0 |
| Open-source sample requested | 5 |
| Sample packages this provider publishes | 0 |
| Sample packages it does not | 5 |

| purl type | Count |
|---|---:|
| `pkg:github` | 42 |

The sample is evidence, not a verdict: no provider is required to publish anybody
else's software. What it establishes is how much of a known open-source set a
catalogue covers, which is the number that makes two providers comparable.

### purl cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| every published PURL identifier is well formed | `queryTeaProducts` | - | - | - | pass |
| a published purl finds its own product | `queryTeaProducts` | 200 | yes | 38.42 ms | pass |
| a purl for a package this provider does not hold matches nothing | `queryTeaProducts` | 200 | yes | 38.35 ms | pass |
| reject a purl that is not a purl | `queryTeaProducts` | 200 | - | 38.42 ms | pass |
| resolve a purl-typed TEI | `discoveryByTei` | 200 | yes | 172.29 ms | pass |
| a purl-typed TEI from another authority is not resolved | `discoveryByTei` | 404 | yes | 172.18 ms | pass |
| open-source sample: 0 of 5 packages resolved | `queryTeaProducts` | - | - | - | pass |


[Back to the summary](../)
