---
title: Conformance report
weight: 2
description: "Independent conformance and performance results for the Vulnetix TEA server against OWASP TEA OpenAPI 0.4.0."
---


| | |
|---|---|
| Verdict | **CONFORMANT** |
| Specification | TEA OpenAPI 0.4.0 |
| Spec source | `https://cyclonedx.github.io/transparency-exchange-api/spec/openapi.yaml` |
| Target | `https://www.vulnetix.com/tea/public/v1` |
| Catalogue | open-source projects, from their published releases |
| Credential | ApiKey credential against a deployed server |
| Generated | 2026-08-01T04:28:26Z |
| Request concurrency | 32 |

## Result

| Metric | Value |
|---|---:|
| Operations declared by the specification | 23 |
| Operations exercised | 23 |
| Test cases | 160 |
| Passed | 160 |
| Failed | 0 |
| Responses schema-validated | 85 |
| Responses conforming to schema | 85 |

## Performance

**Cold start: 367 ms.** That is the first request against a tenant whose object
index is not yet built, which is one aggregate query over the tenant's scan history. Every
subsequent request inside the index's lifetime serves from memory, which is what the
steady-state figures below measure.

Each row replays one request shape 100 times at 32 in flight. Every response was
schema-validated; validation runs after the timer stops, so it does not inflate the
measurement.

| Request | Requests | Failures | p50 | p95 | p99 | max | req/s | body |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| list products | 100 | 0 | 98.54 ms | 118.99 ms | 131.11 ms | 139.76 ms | 300 | 6.1 kB |
| list product releases (full page) | 100 | 0 | 759.06 ms | 1028.06 ms | 1058.59 ms | 1058.65 ms | 39 | 60.2 kB |
| list component releases (full page, descending) | 100 | 0 | 555.28 ms | 911.87 ms | 1072.48 ms | 1697.53 ms | 49 | 51.4 kB |
| read one product | 100 | 0 | 23.41 ms | 115.25 ms | 133.34 ms | 134.49 ms | 607 | 236 B |
| read one product release | 100 | 0 | 39.59 ms | 86.20 ms | 88.09 ms | 88.29 ms | 655 | 637 B |
| releases of one product | 100 | 0 | 37.73 ms | 57.01 ms | 61.11 ms | 62.98 ms | 703 | 3.0 kB |
| component release with latest collection | 100 | 0 | 36.77 ms | 47.54 ms | 48.68 ms | 49.43 ms | 797 | 1.8 kB |
| latest collection | 100 | 0 | 42.27 ms | 66.69 ms | 68.17 ms | 68.57 ms | 701 | 536 B |
| resolve a TEI | 100 | 0 | 23.89 ms | 28.87 ms | 29.94 ms | 30.23 ms | 1081 | 143 B |
| artifact metadata | 100 | 0 | 27.39 ms | 36.13 ms | 36.72 ms | 36.78 ms | 947 | 291 B |

### Conformance-phase latency

The distribution across all 160 conformance cases, one request each including the
error paths, measured client-side to the last byte of the response body, 32 in flight.

| Requests | min | p50 | p95 | p99 | max | mean |
|---:|---:|---:|---:|---:|---:|---:|
| 160 | 21.70 ms | 48.80 ms | 212.85 ms | 257.85 ms | 289.88 ms | 82.86 ms |

## Efficacy

Conformance proves the responses are well-formed. It cannot prove they are complete.
A server that published one artifact per release and dropped the rest would validate
just as cleanly. This section reports what the published graph actually contains.

| Measure | Value |
|---|---:|
| Products sampled | 300 |
| Releases sampled | 24 |
| Collections read | 24 |
| Collections with no artifacts | 3 |
| Artifacts published | 28 |
| Artifacts per collection (mean) | 1.2 |
| Artifacts carrying a checksum | 0 |
| Artifacts carrying a media type | 28 |
| Artifacts carrying a download URL | 28 |
| Artifacts with more than one revision | 0 |
| Deepest artifact revision | 1 |
| Deepest collection version | 2 |
| Releases flagged pre-release | 7 |
| Releases flagged final | 93 |

### Published artifact types

| `artifact-type` | Count |
|---|---:|
| ATTESTATION | 9 |
| RELEASE_NOTES | 19 |

### Published documents

| Document | Count |
|---|---:|
| OpenSSF Scorecard | 9 |
| Release Notes | 19 |

### Artifact revision depth

How many immutable revisions each published artifact has. Depth beyond 1 is TEA's
`(uuid, version)` identity doing real work.

| Revisions | Artifacts |
|---:|---:|
| 1 | 28 |

## Coverage by operation

| Operation | Method | Path | Cases | Pass | Schema OK | p50 | p95 | max | Verdict |
|---|---|---|---:|---:|---:|---:|---:|---:|---|
| `discoveryByTei` | GET | `/discovery` | 6 | 6 | 4/4 | 41.70 ms | 61.07 ms | 61.07 ms | PASS |
| `getArtifactByVersion` | GET | `/artifact/{uuid}/{artifactVersion}` | 4 | 4 | 2/2 | 61.13 ms | 61.46 ms | 61.46 ms | PASS |
| `getCleByComponentId` | GET | `/component/{uuid}/cle` | 3 | 3 | 2/2 | 35.65 ms | 35.80 ms | 35.80 ms | PASS |
| `getCleByComponentReleaseId` | GET | `/componentRelease/{uuid}/cle` | 3 | 3 | 2/2 | 46.30 ms | 65.01 ms | 65.01 ms | PASS |
| `getCleByProductId` | GET | `/product/{uuid}/cle` | 3 | 3 | 2/2 | 121.02 ms | 125.40 ms | 125.40 ms | PASS |
| `getCleByProductReleaseId` | GET | `/productRelease/{uuid}/cle` | 3 | 3 | 2/2 | 197.70 ms | 215.19 ms | 215.19 ms | PASS |
| `getCollection` | GET | `/componentRelease/{uuid}/collection/{collectionVersion}` | 4 | 4 | 2/2 | 32.56 ms | 61.42 ms | 61.42 ms | PASS |
| `getCollectionForProductRelease` | GET | `/productRelease/{uuid}/collection/{collectionVersion}` | 4 | 4 | 2/2 | 126.93 ms | 132.48 ms | 132.48 ms | PASS |
| `getCollectionsByProductReleaseId` | GET | `/productRelease/{uuid}/collections` | 13 | 13 | 6/6 | 139.82 ms | 157.50 ms | 158.38 ms | PASS |
| `getCollectionsByReleaseId` | GET | `/componentRelease/{uuid}/collections` | 13 | 13 | 6/6 | 49.22 ms | 88.72 ms | 90.96 ms | PASS |
| `getComponentReleaseById` | GET | `/componentRelease/{uuid}` | 3 | 3 | 2/2 | 65.91 ms | 65.98 ms | 65.98 ms | PASS |
| `getLatestArtifact` | GET | `/artifact/{uuid}/latest` | 3 | 3 | 2/2 | 61.33 ms | 61.66 ms | 61.66 ms | PASS |
| `getLatestCollection` | GET | `/componentRelease/{uuid}/collection/latest` | 3 | 3 | 2/2 | 45.36 ms | 49.15 ms | 49.15 ms | PASS |
| `getLatestCollectionForProductRelease` | GET | `/productRelease/{uuid}/collection/latest` | 3 | 3 | 2/2 | 197.88 ms | 213.51 ms | 213.51 ms | PASS |
| `getReleasesByComponentId` | GET | `/component/{uuid}/releases` | 13 | 13 | 6/6 | 35.99 ms | 37.63 ms | 37.80 ms | PASS |
| `getReleasesByProductId` | GET | `/product/{uuid}/releases` | 19 | 19 | 12/12 | 46.82 ms | 156.92 ms | 161.27 ms | PASS |
| `getTeaComponentById` | GET | `/component/{uuid}` | 3 | 3 | 2/2 | 23.41 ms | 24.01 ms | 24.01 ms | PASS |
| `getTeaProductByUuid` | GET | `/product/{uuid}` | 4 | 4 | 2/2 | 103.89 ms | 104.01 ms | 104.01 ms | PASS |
| `getTeaProductReleaseByUuid` | GET | `/productRelease/{uuid}` | 3 | 3 | 2/2 | 216.01 ms | 270.69 ms | 270.69 ms | PASS |
| `queryTeaComponentReleases` | GET | `/componentReleases` | 11 | 11 | 5/5 | 47.39 ms | 141.56 ms | 141.56 ms | PASS |
| `queryTeaComponents` | GET | `/components` | 12 | 12 | 5/5 | 24.10 ms | 73.00 ms | 113.99 ms | PASS |
| `queryTeaProductReleases` | GET | `/productReleases` | 12 | 12 | 6/6 | 140.66 ms | 257.85 ms | 289.88 ms | PASS |
| `queryTeaProducts` | GET | `/products` | 14 | 14 | 6/6 | 41.79 ms | 162.48 ms | 162.82 ms | PASS |

## Discovery document

`GET https://www.vulnetix.com/.well-known/tea` (unauthenticated), validated against `tea-well-known.schema.json`: PASS

## Coverage by case category

| Category | Cases | Passed | Failed |
|---|---:|---:|---:|
| conformance | 24 | 24 | 0 |
| discovery | 1 | 1 | 0 |
| filtering | 2 | 2 | 0 |
| negative | 93 | 93 | 0 |
| pagination | 38 | 38 | 0 |
| security | 2 | 2 | 0 |

## Fixtures

The run walked the object graph from `/products` outwards; these are the live identifiers it resolved.

| Object | Identifier |
|---|---|
| TEA Product | `78118e84-eba5-5eb8-82ea-2ba57cbf9740` (666OS/ClashMac) |
| TEA Product Release | `b95dc7ed-f929-58dd-8c03-3bcabc10d290` (version `ClashMac-Legacy`) |
| TEA Component | `077af7e9-7881-5965-89bd-015a03ae00cd` |
| TEA Component Release | `1aa544fe-d842-558a-9386-98b8ecd1bbf5` |
| TEA Artifact | `73a30083-6785-5c70-b8f0-6bbaaafd7cdb` |

## Method

Every response was validated **client-side** against the schema the specification
declares for that operation and status code, compiled directly from the vendored
`openapi.yaml`. OpenAPI 3.1 schema objects are JSON Schema 2020-12, so there is no
translation step between what the specification says and what was enforced here.

Assertions the schemas cannot express, such as collection/release UUID identity, CLE event
ordering, pagination-token consistency and `additionalProperties:false` on error bodies,
were checked separately against the normative prose, and are reported as case failures
in the same way as schema violations.
