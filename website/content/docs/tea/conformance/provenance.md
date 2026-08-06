---
title: Provenance
weight: 8
description: "build provenance, attestations, signatures and checksum coverage"
---


build provenance, attestations, signatures and checksum coverage

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 3 | 3 | 0 | 0 |

## Provenance

TEA's object model is careful about identity, but identity is only worth something if
a consumer can verify it: a checksum matches bytes to a record, a signature matches
the record to a publisher, and an attestation describes the build that produced it. A
publisher can conform to the object specification while supplying none of the three.

| Measure | Value |
|---|---:|
| Artifacts inspected | 112 |
| Carrying a checksum | 112 |
| Carrying a signature | 0 |
| Carrying a media type | 112 |
| With more than one immutable revision | 0 |
| Signatures fetched | 0 |

| Checksum algorithm | Count |
|---|---:|
| SHA-256 | 112 |

Signatures are fetched, not verified: verification needs a trust root this suite has
no way to establish, and inventing one would be worse than saying so.

### provenance cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| 112 of 112 artifacts carry a checksum | `provenanceCoverage` | - | - | - | pass |
| 0 of 112 artifacts carry a signature | `provenanceCoverage` | - | - | - | pass |
| 112 of 112 artifacts carry a media type | `provenanceCoverage` | - | - | - | pass |

#### Detail

**0 of 112 artifacts carry a signature**

- *none do, so a consumer cannot verify who published the record*


[Back to the summary](../)
