---
title: Provider
weight: 10
description: "the publication specification, as a create-read-update-delete round-trip"
---


the publication specification, as a create-read-update-delete round-trip

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 25 | 25 | 0 | 0 |

## Publication

Judged against the publication specification version **0.4.0**, which describes the
`product-component-release` object model.

The round-trip creates objects, revises them, reads them back through the consumption
API, and deletes them. The deletes are conformance cases in their own right and are
also the cleanup: there is no separate teardown, because verifying that delete works
*is* the teardown.

| | |
|---|---|
| Record naming | `owasp-tea-conformance` / `conformance-001` |
| Product identifier | `pkg:generic/owasp-tea-conformance/conformance-001` |
| Objects created | 5 |
| Left behind by a previous run and reclaimed | 0 |
| Residual records | 0 |

### Publisher workflow design

The [TEA Trust Architecture publisher workflow](https://raw.githubusercontent.com/oej/tea-trust-architecture/refs/heads/main/tea-trust-arch/publisher/publisher-workflow.md) is draft, informational design
guidance. The publication OpenAPI document remains the normative conformance source.
This table maps the design to evidence collected by this run; its assessments do not
change the conformance verdict.

| Design concern | Evidence from this run | Assessment |
|---|---|---|
| Stable release identity | 4 of 4 relevant operations completed successfully. Successful collection responses are checked against the stable release UUID and `belongsTo` value; publishing a later version against that same release is not exercised. | partially demonstrated |
| Artifact preparation, signing and validation | 2 of 2 relevant operations completed successfully. The sampled catalogue contained 112 artifacts: 112 carried a checksum and 0 exposed a signature URL. Signature integrity, certificate validity, timestamps, transparency inclusion and collection signatures are not cryptographically verified. | partially demonstrated |
| Collection assembly and signing | 2 of 2 relevant operations completed successfully. The sampled graph contained 24 collections, 0 empty, and 112 referenced artifacts. The round-trip does not prove that a collection was assembled from validated artifact digests or that the collection itself was signed. | partially demonstrated |
| Preparation, separation of duties and approval | CI/CD preparation, publisher-side validation, human approval and separation of roles are internal controls that a black-box HTTP client cannot observe. | not assessed |
| Commit and publication | 2 of 2 relevant operations completed successfully. These read-backs test that accepted writes become visible through the consumption API. Atomic staging, a distinct commit boundary and DNS trust-anchor updates are not exercised. | consumer visibility demonstrated |
| Independent version streams, immutability and history | 2 of 2 relevant operations completed successfully. In the sampled catalogue, 0 artifacts had more than one revision (deepest revision 1), and the deepest collection version was 18. The round-trip reads only `latest`; it does not re-fetch an older artifact, collection or CLE version to prove immutability and continued availability. | partially observed |
| CLE and compliance-document lifecycle | The publication round-trip has no CLE or compliance-document publication case. The read-side SPDX area inspected 10 lifecycle documents, but did not create a new CLE version. | not assessed |

### Records created by this run

| Object | UUID | Label | Deleted | Delete request |
|---|---|---|---|---|
| product | `f28864c6-2e4b-52be-94ec-5086ca559c00` | owasp-tea-conformance conformance-001 | yes | `DELETE /product/f28864c6-2e4b-52be-94ec-5086ca559c00` |
| component | `ed8b5559-0ff5-5257-90c8-4acbd34101fa` | owasp-tea-conformance component conformance-001 | yes | `DELETE /component/ed8b5559-0ff5-5257-90c8-4acbd34101fa` |
| componentRelease | `6b6c0e88-dbc3-573d-88d9-a7f1fca1c6c9` | 0.0.0-conformance | yes | `DELETE /componentRelease/6b6c0e88-dbc3-573d-88d9-a7f1fca1c6c9` |
| productRelease | `5ad9c250-e05a-50cf-a1af-219f9bfa7a19` | 0.0.0-conformance | yes | `DELETE /productRelease/5ad9c250-e05a-50cf-a1af-219f9bfa7a19` |
| artifact | `4a91d0b5-3fcb-50e6-99ec-811161392f6a` | SBOM | yes | `DELETE /artifact/4a91d0b5-3fcb-50e6-99ec-811161392f6a` |

### provider cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| an unauthenticated write is refused | `createTeaProduct` | 401 | - | 19.08 ms | pass |
| look for records left by a previous run | `queryTeaProducts` | 200 | - | 19.84 ms | pass |
| create a product | `createTeaProduct` | 201 | yes | 32.06 ms | pass |
| update the product | `updateTeaProduct` | 200 | yes | 25.47 ms | pass |
| the written product is visible through the consumption API | `getTeaProductByUuid` | 200 | yes | 174.73 ms | pass |
| create a component | `createTeaComponent` | 201 | yes | 32.31 ms | pass |
| create a component release | `createTeaComponentRelease` | 201 | yes | 56.41 ms | pass |
| create a product release pinning the component release | `createTeaProductRelease` | 201 | yes | 43.02 ms | pass |
| publish a collection for the component release | `publishTeaComponentReleaseCollection` | 200 | yes | 45.26 ms | pass |
| publish a collection for the product release | `publishTeaProductReleaseCollection` | 200 | yes | 30.39 ms | pass |
| create a distribution | `createTeaDistribution` | 201 | yes | 68.39 ms | pass |
| create an artifact | `createTeaArtifact` | 201 | yes | 41.64 ms | pass |
| upload the artifact bytes | `uploadTeaArtifactContent` | 200 | yes | 89.15 ms | pass |
| upload a detached signature for the artifact | `uploadTeaArtifactSignature` | 400 | - | 19.13 ms | pass |
| update the artifact's metadata | `updateTeaArtifact` | 200 | yes | 44.83 ms | pass |
| the artifact revision is visible through the consumption API | `getLatestArtifact` | 200 | yes | 311.57 ms | pass |
| the artifact is in the collection it was published against | `getLatestCollection` | 200 | yes | 181.56 ms | pass |
| read the product's access policy | `getTeaAccessPolicy` | 200 | yes | 43.84 ms | pass |
| set the product's access policy to private | `setTeaAccessPolicy` | 200 | yes | 61.47 ms | pass |
| delete the artifact | `deleteTeaArtifact` | 204 | - | 22.88 ms | pass |
| delete the productRelease | `deleteTeaProductRelease` | 204 | - | 23.75 ms | pass |
| delete the componentRelease | `deleteTeaComponentRelease` | 204 | - | 28.85 ms | pass |
| delete the component | `deleteTeaComponent` | 204 | - | 24.88 ms | pass |
| delete the product | `deleteTeaProduct` | 204 | - | 21.85 ms | pass |
| the deleted product is gone from the consumption API | `getTeaProductByUuid` | 404 | yes | 139.84 ms | pass |


[Back to the summary](../)
