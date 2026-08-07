---
title: CycloneDX
weight: 4
description: "the published BOM documents, validated against the version each declares"
---


the published BOM documents, validated against the version each declares

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 26 | 26 | 0 | 0 |

## CycloneDX documents

The BOM documents behind the artifact records, downloaded and validated against the
version each one declares.

| Measure | Value |
|---|---:|
| BOM artifacts found | 54 |
| Downloaded and validated | 25 |
| Not downloaded (per-run limit) | 29 |

| CycloneDX version | Documents |
|---|---:|
| 1.6 | 7 |
| 1.7 | 18 |

| Document | Product | Version | Components | Valid |
|---|---|---|---:|---|
| Cryptography Bill of Materials | Vulnetix/osm-submitter | 1.7 | 10 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/vdb-sca-match | 1.7 | 1 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/cli | 1.7 | 5 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/vdb-site | 1.7 | 6 | yes |
| Cryptography Bill of Materials | Vulnetix/sca-manifest-fixtures | 1.7 | 3 | yes |
| AI Bill of Materials | Vulnetix/headshot | 1.7 | 1 | yes |
| AI Bill of Materials | Vulnetix/vdb-api | 1.7 | 5 | yes |
| Cryptography Bill of Materials | Vulnetix/vdb-site | 1.7 | 5 | yes |
| AI Bill of Materials | Vulnetix/vdb-site | 1.7 | 2 | yes |
| Cryptography Bill of Materials | Vulnetix/vdb-api | 1.7 | 8 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/headshot | 1.7 | 10 | yes |
| Vulnetix SCA Software Bill of Materials | Vulnetix/opa-cds-aws-tf | 1.6 | 3 | yes |
| Vulnetix SCA Software Bill of Materials | Vulnetix/opa-cigna-tf | 1.6 | 3 | yes |
| AI Bill of Materials | Vulnetix/cli | 1.7 | 2 | yes |
| Vulnetix SCA Software Bill of Materials | Vulnetix/community-rules | 1.6 | 3 | yes |
| vulnetix-containers Software Bill of Materials | Vulnetix/cli | 1.6 | 3 | yes |
| sbom.cdx.json | Vulnetix/vdb-cyclonedx | 1.7 | 43 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/vdb-api | 1.7 | 5 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/vdb-sca-match | 1.6 | 24 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/python-ssvc | 1.7 | 2 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/python-ssvc | 1.6 | 25 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/vdb-api | 1.6 | 25 | yes |
| AI Bill of Materials | Vulnetix/sca-manifest-fixtures | 1.7 | 1 | yes |
| cbom.cdx.json | Vulnetix/ai-firewall | 1.7 | 3 | yes |
| Cryptography Bill of Materials | Vulnetix/cli | 1.7 | 40 | yes |

### cyclonedx cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| 29 further BOM document(s) were not downloaded (limit 25) | `-` | - | - | - | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/osm-submitter | `artifactDownload` | 200 | yes | 309.08 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/vdb-sca-match | `artifactDownload` | 200 | yes | 506.19 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/cli | `artifactDownload` | 200 | yes | 642.12 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/vdb-site | `artifactDownload` | 200 | yes | 468.72 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/sca-manifest-fixtures | `artifactDownload` | 200 | yes | 309.27 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/headshot | `artifactDownload` | 200 | yes | 308.93 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 309.86 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/vdb-site | `artifactDownload` | 200 | yes | 309.10 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/vdb-site | `artifactDownload` | 200 | yes | 281.88 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 308.98 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/headshot | `artifactDownload` | 200 | yes | 613.85 ms | pass |
| download and validate Vulnetix SCA Software Bill of Materials of Vulnetix/opa-cds-aws-tf | `artifactDownload` | 200 | yes | 600.00 ms | pass |
| download and validate Vulnetix SCA Software Bill of Materials of Vulnetix/opa-cigna-tf | `artifactDownload` | 200 | yes | 387.71 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/cli | `artifactDownload` | 200 | yes | 311.32 ms | pass |
| download and validate Vulnetix SCA Software Bill of Materials of Vulnetix/community-rules | `artifactDownload` | 200 | yes | 533.80 ms | pass |
| download and validate vulnetix-containers Software Bill of Materials of Vulnetix/cli | `artifactDownload` | 200 | yes | 442.14 ms | pass |
| download and validate sbom.cdx.json of Vulnetix/vdb-cyclonedx | `artifactDownload` | 200 | yes | 1271.53 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 652.29 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/vdb-sca-match | `artifactDownload` | 200 | yes | 351.96 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/python-ssvc | `artifactDownload` | 200 | yes | 353.01 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/python-ssvc | `artifactDownload` | 200 | yes | 1244.07 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 675.06 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/sca-manifest-fixtures | `artifactDownload` | 200 | yes | 308.81 ms | pass |
| download and validate cbom.cdx.json of Vulnetix/ai-firewall | `artifactDownload` | 200 | yes | 662.83 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/cli | `artifactDownload` | 200 | yes | 309.30 ms | pass |


[Back to the summary](../)
