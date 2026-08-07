---
title: Consumer
weight: 2
description: "every operation of the consumption specification, including its error paths"
---


every operation of the consumption specification, including its error paths

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 158 | 157 | 0 | 1 |

## Fixtures

The run walked the object graph outwards from `/products`; these are the live
identifiers it resolved. Seeding from the API instead of from constants is what makes
a green run mean the graph is navigable, and not simply that a fixture exists.

| Object | Identifier |
|---|---|
| TEA Product | `36117cc1-7417-572f-8ac2-efe2bb6587b2` (Vulnetix/ai-firewall) |
| TEA Product Release | `ae59594d-d833-57b6-bb70-e44b19b32a08` (version `111d521b4d0c7fb8c742ad14dc1765333fd60801`) |
| TEA Component | `bfe0d6a9-9007-5541-8284-e44d02d5c32a` |
| TEA Component Release | `92ee4ed8-2b0f-5be0-8316-2901af2f174a` |
| TEA Artifact | `8ebab5c4-cdac-4753-b664-4ea8cc539491` |
| TEI authority | `vulnetix.com` |

## Artifact retrieval and trust validation

The [TEA Consumer API artifact-retrieval document](https://github.com/oej/tea-trust-architecture/blob/main/tea-trust-arch/consumer/artifact-retrieval.md), version 1.0, describes a draft,
normative profile layered over the consumption API. It distinguishes Base TEA from TEA
with the Trust Architecture and from a high-assurance profile. The configured consumption
OpenAPI remains the source of the overall verdict; this table reports the additional
profile requirements separately. Because independent evidence-bundle retrieval is not
exercised, this run does **not demonstrate conformance to the Trust Architecture profile**,
even where Base TEA artifact retrieval succeeds.

| Requirement or profile | Evidence from this run | Assessment |
|---|---|---|
| Base TEA: artifact retrieval (MUST) | Artifact metadata: 7 requests were exercised, 2 returned content successfully, and 7 passed their applicable checks. Artifact content: 25 requests were exercised, 25 returned content successfully, and 25 passed their applicable checks. The sampled catalogue exposed a download URL for 130 of 130 artifacts. Content URLs were learned through collections; retrieval by artifact identity without first reading a collection was not probed. | partially demonstrated |
| Detached-signature retrieval (MAY) | The sampled catalogue exposed 0 detached-signature URLs; no matching request was exercised. Fetched signatures are not cryptographically verified and do not establish timestamp, transparency or long-term validity. | not observed (optional) |
| Trust Architecture: independent evidence-bundle retrieval (MUST) | No conformance case in this run retrieved an evidence bundle independently of a collection or tied a bundle to the returned artifact. Attestation artifacts and detached signatures are not treated as substitutes for an evidence bundle. | not demonstrated |
| Artifact plus evidence-bundle multipart retrieval (SHOULD) | This run did not negotiate `multipart/mixed; profile="artifact+evidence"`, identify its two parts, or test artifact and bundle mismatch handling. | not assessed |
| Validation behavior and transport-versus-trust semantics | 25 artifact-content responses were retrieved and 25 passed their applicable document and digest checks. 130 of 130 sampled artifact records carried a checksum. Certificate chains, timestamp evidence, transparency inclusion and local trust policy were not validated. | content integrity partially demonstrated |
| Collection inclusion versus independent authenticity | Collection UUID and `belongsTo` rules are checked by the consumption cases. Artifact/evidence reuse across collections, and authenticity validation without a collection, are not exercised. | partially assessed |
| Error handling | 5 artifact metadata error-path cases were exercised; 5 conformed. The trust-profile errors for missing evidence, unsupported multipart profiles and artifact/evidence or artifact/signature mismatch were not exercised. | base errors partially demonstrated |
| High-assurance profile | Bundle caching and reuse, offline validation, and operation without live timestamp or transparency services are outside this black-box run. | not assessed |

## Efficacy

Conformance proves the responses are well formed. It cannot prove they are complete:
a server that published one artifact per release and dropped the rest would validate
just as cleanly. This is what the published graph actually contains.

| Measure | Value |
|---|---:|
| Products published | 42 |
| Releases sampled | 24 |
| Collections read | 24 |
| Collections with no artifacts | 0 |
| Artifacts published | 130 |
| Artifacts per collection (mean) | 5.4 |
| Artifacts carrying a checksum | 130 |
| Artifacts carrying a media type | 130 |
| Artifacts carrying a download URL | 130 |
| Artifacts carrying a signature | 0 |
| Artifacts with more than one revision | 0 |
| Deepest artifact revision | 1 |
| Deepest collection version | 19 |
| Releases flagged pre-release | 2 |
| Releases flagged final | 98 |

### Published artifact types

| `artifact-type` | Count |
|---|---:|
| BOM | 47 |
| BUILD_META | 56 |
| OTHER | 1 |
| VULNERABILITIES | 26 |

### Published documents

| Document | Count |
|---|---:|
| AI Bill of Materials | 7 |
| Build manifest .github/workflows/api-ci.yml | 1 |
| Build manifest .github/workflows/api-deploy.yml | 2 |
| Build manifest .github/workflows/auto-version.yml | 1 |
| Build manifest .github/workflows/ci.yml | 2 |
| Build manifest .github/workflows/docs.yml | 1 |
| Build manifest .github/workflows/ecr-deploy.yml | 1 |
| Build manifest .github/workflows/frontend-ci.yml | 1 |
| Build manifest .github/workflows/frontend-deploy.yml | 1 |
| Build manifest .github/workflows/http-tests.yml | 1 |
| Build manifest .github/workflows/lint.yml | 1 |
| Build manifest .github/workflows/pages.yml | 1 |
| Build manifest .github/workflows/release.yml | 1 |
| Build manifest .github/workflows/reporter-deploy.yml | 1 |
| Build manifest .github/workflows/sca.yml | 1 |
| Build manifest .github/workflows/terraform.yml | 1 |
| Build manifest .github/workflows/test.yml | 1 |
| Build manifest .github/workflows/vulnetix.yml | 15 |
| Build manifest Dockerfile | 1 |
| Build manifest api/go.mod | 2 |
| Build manifest api/go.sum | 2 |
| Build manifest frontend/package-lock.json | 1 |
| Build manifest frontend/package.json | 1 |
| Build manifest go.mod | 3 |
| Build manifest go.sum | 3 |
| Build manifest lambda/go.mod | 1 |
| Build manifest lambda/go.sum | 1 |
| Build manifest pyproject.toml | 1 |
| Build manifest reporter/go.mod | 1 |
| Build manifest reporter/go.sum | 1 |
| Build manifest tests/package-lock.json | 1 |
| Build manifest tests/package.json | 1 |
| Build manifest uv.lock | 1 |
| Build manifest web/package.json | 1 |
| Build manifest web/yarn.lock | 1 |
| Cryptography Bill of Materials | 9 |
| Repository Analysis Report | 1 |
| Vulnetix SAST Findings Report | 1 |
| Vulnetix SAST Vulnerability Exploitability eXchange | 1 |
| Vulnetix SCA Monitor Software Bill of Materials | 9 |
| Vulnetix SCA Software Bill of Materials | 10 |
| Vulnetix SCA Vulnerability Exploitability eXchange | 7 |
| Vulnetix Secrets Findings Report | 8 |
| Vulnetix Secrets Vulnerability Exploitability eXchange | 8 |
| ai-bom.cdx.json | 4 |
| cbom.cdx.json | 4 |
| sbom.cdx.json | 3 |
| vulnetix-containers OCI Findings Report | 1 |
| vulnetix-containers Software Bill of Materials | 1 |

### Artifact revision depth

How many immutable revisions each published artifact has. Depth beyond 1 is TEA's
`(uuid, version)` identity doing real work.

| Revisions | Artifacts |
|---:|---:|
| 1 | 130 |

### consumer cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| default page | `queryTeaProducts` | 200 | yes | 47.13 ms | pass |
| explicit page size | `queryTeaProducts` | 200 | yes | 461.63 ms | pass |
| maximum page size | `queryTeaProducts` | 200 | yes | 241.64 ms | pass |
| follow nextPageToken | `queryTeaProducts` | 200 | yes | 47.11 ms | pass |
| reject pageSize below minimum | `queryTeaProducts` | 400 | - | 241.75 ms | pass |
| reject pageSize above maximum | `queryTeaProducts` | 400 | - | 232.98 ms | pass |
| reject non-numeric pageSize | `queryTeaProducts` | 400 | - | 461.52 ms | pass |
| reject foreign pageToken | `queryTeaProducts` | 400 | - | 233.08 ms | pass |
| reject unknown sortField | `queryTeaProducts` | 400 | - | 242.06 ms | pass |
| reject unknown sortOrder | `queryTeaProducts` | 400 | - | 233.09 ms | pass |
| descending order | `queryTeaProducts` | 200 | yes | 233.17 ms | pass |
| filter by PURL identifier | `queryTeaProducts` | 200 | yes | 47.88 ms | pass |
| reject unknown idType | `queryTeaProducts` | 400 | - | 241.71 ms | pass |
| existing object | `getTeaProductByUuid` | 200 | yes | 233.10 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getTeaProductByUuid` | 404 | yes | 245.51 ms | pass |
| malformed uuid is rejected | `getTeaProductByUuid` | 400 | - | 233.17 ms | pass |
| default page | `getReleasesByProductId` | 200 | yes | 241.95 ms | pass |
| explicit page size | `getReleasesByProductId` | 200 | yes | 233.16 ms | pass |
| maximum page size | `getReleasesByProductId` | 200 | yes | 241.42 ms | pass |
| follow nextPageToken | `getReleasesByProductId` | 200 | yes | 233.12 ms | pass |
| reject pageSize below minimum | `getReleasesByProductId` | 400 | - | 461.83 ms | pass |
| reject pageSize above maximum | `getReleasesByProductId` | 400 | - | 242.04 ms | pass |
| reject non-numeric pageSize | `getReleasesByProductId` | 400 | - | 47.57 ms | pass |
| reject foreign pageToken | `getReleasesByProductId` | 400 | - | 32.04 ms | pass |
| reject unknown sortField | `getReleasesByProductId` | 400 | - | 241.79 ms | pass |
| reject unknown sortOrder | `getReleasesByProductId` | 400 | - | 461.58 ms | pass |
| descending order | `getReleasesByProductId` | 200 | yes | 232.77 ms | pass |
| absent parent reports OBJECT_UNKNOWN | `getReleasesByProductId` | 404 | yes | 245.29 ms | pass |
| malformed parent uuid is rejected | `getReleasesByProductId` | 400 | - | 462.15 ms | pass |
| sort by createdDate asc | `getReleasesByProductId` | 200 | yes | 473.52 ms | pass |
| sort by createdDate desc | `getReleasesByProductId` | 200 | yes | 245.20 ms | pass |
| sort by releaseDate asc | `getReleasesByProductId` | 200 | yes | 46.89 ms | pass |
| sort by releaseDate desc | `getReleasesByProductId` | 200 | yes | 438.46 ms | pass |
| sort by version asc | `getReleasesByProductId` | 200 | yes | 197.76 ms | pass |
| sort by version desc | `getReleasesByProductId` | 200 | yes | 185.13 ms | pass |
| existing object | `getCleByProductId` | 200 | yes | 197.28 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getCleByProductId` | 404 | yes | 197.15 ms | pass |
| malformed uuid is rejected | `getCleByProductId` | 400 | - | 184.09 ms | pass |
| default page | `queryTeaProductReleases` | 200 | yes | 28.99 ms | pass |
| explicit page size | `queryTeaProductReleases` | 200 | yes | 229.06 ms | pass |
| maximum page size | `queryTeaProductReleases` | 200 | yes | 80.30 ms | pass |
| follow nextPageToken | `queryTeaProductReleases` | 200 | yes | 45.65 ms | pass |
| reject pageSize below minimum | `queryTeaProductReleases` | 400 | - | 228.70 ms | pass |
| reject pageSize above maximum | `queryTeaProductReleases` | 400 | - | 45.55 ms | pass |
| reject non-numeric pageSize | `queryTeaProductReleases` | 400 | - | 45.55 ms | pass |
| reject foreign pageToken | `queryTeaProductReleases` | 400 | - | 45.38 ms | pass |
| reject unknown sortField | `queryTeaProductReleases` | 400 | - | 45.24 ms | pass |
| reject unknown sortOrder | `queryTeaProductReleases` | 400 | - | 45.14 ms | pass |
| descending order | `queryTeaProductReleases` | 200 | yes | 228.65 ms | pass |
| filter by TEI identifier | `queryTeaProductReleases` | 200 | yes | 70.77 ms | pass |
| existing object | `getTeaProductReleaseByUuid` | 200 | yes | 70.60 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getTeaProductReleaseByUuid` | 404 | yes | 70.49 ms | pass |
| malformed uuid is rejected | `getTeaProductReleaseByUuid` | 400 | - | 70.39 ms | pass |
| existing object | `getCleByProductReleaseId` | 200 | yes | 70.56 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getCleByProductReleaseId` | 404 | yes | 69.96 ms | pass |
| malformed uuid is rejected | `getCleByProductReleaseId` | 400 | - | 69.61 ms | pass |
| existing object | `getLatestCollectionForProductRelease` | 200 | yes | 219.18 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getLatestCollectionForProductRelease` | 404 | yes | 67.21 ms | pass |
| malformed uuid is rejected | `getLatestCollectionForProductRelease` | 400 | - | 215.91 ms | pass |
| default page | `getCollectionsByProductReleaseId` | 200 | yes | 173.40 ms | pass |
| explicit page size | `getCollectionsByProductReleaseId` | 200 | yes | 66.88 ms | pass |
| maximum page size | `getCollectionsByProductReleaseId` | 200 | yes | 131.16 ms | pass |
| follow nextPageToken | `getCollectionsByProductReleaseId` | 200 | yes | 224.76 ms | pass |
| reject pageSize below minimum | `getCollectionsByProductReleaseId` | 400 | - | 49.15 ms | pass |
| reject pageSize above maximum | `getCollectionsByProductReleaseId` | 400 | - | 97.87 ms | pass |
| reject non-numeric pageSize | `getCollectionsByProductReleaseId` | 400 | - | 97.83 ms | pass |
| reject foreign pageToken | `getCollectionsByProductReleaseId` | 400 | - | 97.88 ms | pass |
| reject unknown sortField | `getCollectionsByProductReleaseId` | 400 | - | 97.88 ms | pass |
| reject unknown sortOrder | `getCollectionsByProductReleaseId` | 400 | - | 97.87 ms | pass |
| descending order | `getCollectionsByProductReleaseId` | 200 | yes | 182.29 ms | pass |
| absent parent reports OBJECT_UNKNOWN | `getCollectionsByProductReleaseId` | 404 | yes | 148.32 ms | pass |
| malformed parent uuid is rejected | `getCollectionsByProductReleaseId` | 400 | - | 147.83 ms | pass |
| first version | `getCollectionForProductRelease` | 200 | yes | 148.58 ms | pass |
| version beyond history is unknown | `getCollectionForProductRelease` | 404 | yes | 148.14 ms | pass |
| reject non-integer collectionVersion | `getCollectionForProductRelease` | 400 | - | 148.07 ms | pass |
| reject zero collectionVersion | `getCollectionForProductRelease` | 400 | - | 148.05 ms | pass |
| default page | `queryTeaComponents` | 200 | yes | 148.00 ms | pass |
| explicit page size | `queryTeaComponents` | 200 | yes | 147.60 ms | pass |
| maximum page size | `queryTeaComponents` | 200 | yes | 147.84 ms | pass |
| follow nextPageToken | `queryTeaComponents` | 200 | yes | 147.41 ms | pass |
| reject pageSize below minimum | `queryTeaComponents` | 400 | - | 146.01 ms | pass |
| reject pageSize above maximum | `queryTeaComponents` | 400 | - | 84.21 ms | pass |
| reject non-numeric pageSize | `queryTeaComponents` | 400 | - | 84.67 ms | pass |
| reject foreign pageToken | `queryTeaComponents` | 400 | - | 84.17 ms | pass |
| reject unknown sortField | `queryTeaComponents` | 400 | - | 84.23 ms | pass |
| reject unknown sortOrder | `queryTeaComponents` | 400 | - | 84.68 ms | pass |
| descending order | `queryTeaComponents` | 200 | yes | 81.65 ms | pass |
| reject unknown idType | `queryTeaComponents` | 400 | - | 37.62 ms | pass |
| existing object | `getTeaComponentById` | 200 | yes | 29.76 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getTeaComponentById` | 404 | yes | 34.34 ms | pass |
| malformed uuid is rejected | `getTeaComponentById` | 400 | - | 33.04 ms | pass |
| default page | `getReleasesByComponentId` | 200 | yes | 27.20 ms | pass |
| explicit page size | `getReleasesByComponentId` | 200 | yes | 34.24 ms | pass |
| maximum page size | `getReleasesByComponentId` | 200 | yes | 29.80 ms | pass |
| follow nextPageToken | `getReleasesByComponentId` | 200 | yes | 30.82 ms | pass |
| reject pageSize below minimum | `getReleasesByComponentId` | 400 | - | 33.33 ms | pass |
| reject pageSize above maximum | `getReleasesByComponentId` | 400 | - | 33.13 ms | pass |
| reject non-numeric pageSize | `getReleasesByComponentId` | 400 | - | 30.80 ms | pass |
| reject foreign pageToken | `getReleasesByComponentId` | 400 | - | 33.93 ms | pass |
| reject unknown sortField | `getReleasesByComponentId` | 400 | - | 29.43 ms | pass |
| reject unknown sortOrder | `getReleasesByComponentId` | 400 | - | 35.05 ms | pass |
| descending order | `getReleasesByComponentId` | 200 | yes | 33.57 ms | pass |
| absent parent reports OBJECT_UNKNOWN | `getReleasesByComponentId` | 404 | yes | 63.92 ms | pass |
| malformed parent uuid is rejected | `getReleasesByComponentId` | 400 | - | 33.38 ms | pass |
| existing object | `getCleByComponentId` | 200 | yes | 63.80 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getCleByComponentId` | 404 | yes | 63.33 ms | pass |
| malformed uuid is rejected | `getCleByComponentId` | 400 | - | 34.11 ms | pass |
| default page | `queryTeaComponentReleases` | 200 | yes | 47.65 ms | pass |
| explicit page size | `queryTeaComponentReleases` | 200 | yes | 63.14 ms | pass |
| maximum page size | `queryTeaComponentReleases` | 200 | yes | 85.75 ms | pass |
| follow nextPageToken | `queryTeaComponentReleases` | 200 | yes | 33.88 ms | pass |
| reject pageSize below minimum | `queryTeaComponentReleases` | 400 | - | 33.66 ms | pass |
| reject pageSize above maximum | `queryTeaComponentReleases` | 400 | - | 33.62 ms | pass |
| reject non-numeric pageSize | `queryTeaComponentReleases` | 400 | - | 62.41 ms | pass |
| reject foreign pageToken | `queryTeaComponentReleases` | 400 | - | 62.50 ms | pass |
| reject unknown sortField | `queryTeaComponentReleases` | 400 | - | 62.51 ms | pass |
| reject unknown sortOrder | `queryTeaComponentReleases` | 400 | - | 61.02 ms | pass |
| descending order | `queryTeaComponentReleases` | 200 | yes | 55.60 ms | pass |
| existing object | `getComponentReleaseById` | 200 | yes | 55.42 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getComponentReleaseById` | 404 | yes | 75.14 ms | pass |
| malformed uuid is rejected | `getComponentReleaseById` | 400 | - | 59.48 ms | pass |
| existing object | `getCleByComponentReleaseId` | 200 | yes | 57.48 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getCleByComponentReleaseId` | 404 | yes | 57.40 ms | pass |
| malformed uuid is rejected | `getCleByComponentReleaseId` | 400 | - | 57.05 ms | pass |
| existing object | `getLatestCollection` | 200 | yes | 56.26 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getLatestCollection` | 404 | yes | 56.11 ms | pass |
| malformed uuid is rejected | `getLatestCollection` | 400 | - | 53.88 ms | pass |
| default page | `getCollectionsByReleaseId` | 200 | yes | 63.64 ms | pass |
| explicit page size | `getCollectionsByReleaseId` | 200 | yes | 53.81 ms | pass |
| maximum page size | `getCollectionsByReleaseId` | 200 | yes | 106.38 ms | pass |
| follow nextPageToken | `getCollectionsByReleaseId` | 200 | yes | 93.33 ms | pass |
| reject pageSize below minimum | `getCollectionsByReleaseId` | 400 | - | 62.57 ms | pass |
| reject pageSize above maximum | `getCollectionsByReleaseId` | 400 | - | 52.99 ms | pass |
| reject non-numeric pageSize | `getCollectionsByReleaseId` | 400 | - | 62.12 ms | pass |
| reject foreign pageToken | `getCollectionsByReleaseId` | 400 | - | 92.05 ms | pass |
| reject unknown sortField | `getCollectionsByReleaseId` | 400 | - | 92.10 ms | pass |
| reject unknown sortOrder | `getCollectionsByReleaseId` | 400 | - | 91.95 ms | pass |
| descending order | `getCollectionsByReleaseId` | 200 | yes | 155.32 ms | pass |
| absent parent reports OBJECT_UNKNOWN | `getCollectionsByReleaseId` | 404 | yes | 104.81 ms | pass |
| malformed parent uuid is rejected | `getCollectionsByReleaseId` | 400 | - | 140.69 ms | pass |
| first version | `getCollection` | 200 | yes | 125.51 ms | pass |
| version beyond history is unknown | `getCollection` | 404 | yes | 125.67 ms | pass |
| reject non-integer collectionVersion | `getCollection` | 400 | - | 125.61 ms | pass |
| reject zero collectionVersion | `getCollection` | 400 | - | 125.61 ms | pass |
| existing object | `getLatestArtifact` | 200 | yes | 125.91 ms | pass |
| absent object reports OBJECT_UNKNOWN | `getLatestArtifact` | 404 | yes | 125.56 ms | pass |
| malformed uuid is rejected | `getLatestArtifact` | 400 | - | 125.32 ms | pass |
| first revision | `getArtifactByVersion` | 200 | yes | 124.95 ms | pass |
| revision beyond history is unknown | `getArtifactByVersion` | 404 | yes | 124.92 ms | pass |
| reject non-integer version | `getArtifactByVersion` | 400 | - | 124.42 ms | pass |
| reject malformed uuid | `getArtifactByVersion` | 400 | - | 103.46 ms | pass |
| resolve uuid TEI | `discoveryByTei` | 200 | yes | 103.64 ms | pass |
| reject TEI from another authority | `discoveryByTei` | 404 | yes | 103.51 ms | pass |
| unknown identifier in this authority | `discoveryByTei` | 404 | yes | 103.41 ms | pass |
| reject missing tei parameter | `discoveryByTei` | 400 | - | 103.50 ms | pass |
| reject malformed urn | `discoveryByTei` | 400 | - | 103.39 ms | pass |
| anonymous listing is refused | `queryTeaProducts` | 200 | - | 103.50 ms | advisory |
| anonymous object read is refused | `getTeaProductByUuid` | 404 | - | 103.33 ms | pass |

#### Detail

**anonymous listing is refused**: `GET https://www.vulnetix.com/tea/v0.4.0/products`

- expected HTTP 401, got 200: {"hasNext":false,"nextPageToken":"","results":[{"uuid":"54e8820d-0803-5a4f-858d-88a279486564","name":"Vulnetix/cli","identifiers":[{"idType":"TEI","idValue":"urn:tei:uuid:vulnetix.com:54e8820d-0803-5a4f-858d-88a279486564...
- evidence: `responses/consumer/0157-get-anonymous-listing-is-refused.meta.json`


[Back to the summary](../)
