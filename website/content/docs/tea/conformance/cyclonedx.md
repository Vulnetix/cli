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
| BOM artifacts found | 50 |
| Downloaded and validated | 25 |
| Not downloaded (per-run limit) | 25 |

| CycloneDX version | Documents |
|---|---:|
| 1.6 | 9 |
| 1.7 | 16 |

| Document | Product | Version | Components | Valid |
|---|---|---|---:|---|
| Cryptography Bill of Materials | Vulnetix/osm-submitter | 1.7 | 10 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/python-ssvc | 1.6 | 12 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/vdb-sca-match | 1.7 | 1 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/cli | 1.7 | 5 | yes |
| Cryptography Bill of Materials | Vulnetix/sca-manifest-fixtures | 1.7 | 3 | yes |
| AI Bill of Materials | Vulnetix/headshot | 1.7 | 1 | yes |
| AI Bill of Materials | Vulnetix/vdb-api | 1.7 | 5 | yes |
| Cryptography Bill of Materials | Vulnetix/vdb-api | 1.7 | 8 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/headshot | 1.7 | 10 | yes |
| Vulnetix SCA Software Bill of Materials | Vulnetix/opa-cds-aws-tf | 1.6 | 3 | yes |
| Vulnetix SCA Software Bill of Materials | Vulnetix/opa-cigna-tf | 1.6 | 3 | yes |
| Cryptography Bill of Materials | Vulnetix/vdb-site | 1.7 | 14 | yes |
| AI Bill of Materials | Vulnetix/cli | 1.7 | 2 | yes |
| Vulnetix SCA Software Bill of Materials | Vulnetix/community-rules | 1.6 | 3 | yes |
| vulnetix-containers Software Bill of Materials | Vulnetix/cli | 1.6 | 3 | yes |
| sbom.cdx.json | Vulnetix/vdb-cyclonedx | 1.7 | 43 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/vdb-api | 1.7 | 5 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/vdb-sca-match | 1.6 | 24 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/vdb-api | 1.6 | 25 | yes |
| AI Bill of Materials | Vulnetix/sca-manifest-fixtures | 1.7 | 1 | yes |
| cbom.cdx.json | Vulnetix/ai-firewall | 1.7 | 3 | yes |
| Cryptography Bill of Materials | Vulnetix/cli | 1.7 | 40 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/s3-queue-gui | 1.6 | 25 | yes |
| sbom.cdx.json | Vulnetix/github-runner-aws | 1.7 | 29 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/osm-submitter | 1.6 | 25 | yes |

### cyclonedx cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| 25 further BOM document(s) were not downloaded (limit 25) | `-` | - | - | - | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/osm-submitter | `artifactDownload` | 200 | yes | 536.08 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/python-ssvc | `artifactDownload` | 200 | yes | 3525.14 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/vdb-sca-match | `artifactDownload` | 200 | yes | 1535.51 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/cli | `artifactDownload` | 200 | yes | 1599.81 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/sca-manifest-fixtures | `artifactDownload` | 200 | yes | 282.01 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/headshot | `artifactDownload` | 200 | yes | 322.61 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 306.23 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 731.95 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/headshot | `artifactDownload` | 200 | yes | 4838.35 ms | pass |
| download and validate Vulnetix SCA Software Bill of Materials of Vulnetix/opa-cds-aws-tf | `artifactDownload` | 200 | yes | 731.87 ms | pass |
| download and validate Vulnetix SCA Software Bill of Materials of Vulnetix/opa-cigna-tf | `artifactDownload` | 200 | yes | 1494.42 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/vdb-site | `artifactDownload` | 200 | yes | 731.82 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/cli | `artifactDownload` | 200 | yes | 731.90 ms | pass |
| download and validate Vulnetix SCA Software Bill of Materials of Vulnetix/community-rules | `artifactDownload` | 200 | yes | 1096.20 ms | pass |
| download and validate vulnetix-containers Software Bill of Materials of Vulnetix/cli | `artifactDownload` | 200 | yes | 1584.42 ms | pass |
| download and validate sbom.cdx.json of Vulnetix/vdb-cyclonedx | `artifactDownload` | 200 | yes | 3673.40 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 1005.22 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/vdb-sca-match | `artifactDownload` | 200 | yes | 3564.37 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 1998.38 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/sca-manifest-fixtures | `artifactDownload` | 200 | yes | 275.27 ms | pass |
| download and validate cbom.cdx.json of Vulnetix/ai-firewall | `artifactDownload` | 200 | yes | 3242.87 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/cli | `artifactDownload` | 200 | yes | 802.88 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/s3-queue-gui | `artifactDownload` | 200 | yes | 1067.52 ms | pass |
| download and validate sbom.cdx.json of Vulnetix/github-runner-aws | `artifactDownload` | 200 | yes | 1799.24 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/osm-submitter | `artifactDownload` | 200 | yes | 2212.95 ms | pass |


[Back to the summary](../)
