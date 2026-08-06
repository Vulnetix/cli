---
title: CycloneDX
weight: 4
description: "the published BOM documents, validated against the version each declares"
---


the published BOM documents, validated against the version each declares

| Cases | Passed | Failed | Advisory |
|---:|---:|---:|---:|
| 26 | 22 | 4 | 0 |

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
| 1.6 | 8 |
| 1.7 | 17 |

| Document | Product | Version | Components | Valid |
|---|---|---|---:|---|
| Cryptography Bill of Materials | Vulnetix/osm-submitter | 1.7 | 10 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/vdb-sca-match | 1.6 | 24 | **no** |
| AI Bill of Materials | Vulnetix/headshot | 1.7 | 1 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/vdb-sca-match | 1.7 | 2 | **no** |
| Cryptography Bill of Materials | Vulnetix/sca-manifest-fixtures | 1.7 | 3 | yes |
| AI Bill of Materials | Vulnetix/vdb-api | 1.7 | 5 | yes |
| Vulnetix SCA Software Bill of Materials | Vulnetix/opa-cds-aws-tf | 1.6 | 3 | yes |
| Vulnetix SCA Software Bill of Materials | Vulnetix/opa-cigna-tf | 1.6 | 3 | yes |
| Vulnetix SCA Software Bill of Materials | Vulnetix/community-rules | 1.6 | 3 | yes |
| sbom.cdx.json | Vulnetix/vdb-cyclonedx | 1.7 | 43 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/vdb-api | 1.7 | 6 | **no** |
| AI Bill of Materials | Vulnetix/cli | 1.7 | 2 | yes |
| Cryptography Bill of Materials | Vulnetix/headshot | 1.7 | 3 | yes |
| Vulnetix SCA Vulnerability Exploitability eXchange | Vulnetix/python-ssvc | 1.7 | 2 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/python-ssvc | 1.6 | 25 | yes |
| Cryptography Bill of Materials | Vulnetix/s3-queue-gui | 1.7 | 1 | yes |
| vulnetix-containers Software Bill of Materials | Vulnetix/vdb-site | 1.6 | 4 | yes |
| Cryptography Bill of Materials | Vulnetix/vdb-api | 1.7 | 8 | yes |
| AI Bill of Materials | Vulnetix/sca-manifest-fixtures | 1.7 | 1 | yes |
| cbom.cdx.json | Vulnetix/ai-firewall | 1.7 | 3 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/vdb-api | 1.6 | 25 | **no** |
| sbom.cdx.json | Vulnetix/github-runner-aws | 1.7 | 29 | yes |
| Vulnetix SCA Monitor Software Bill of Materials | Vulnetix/osm-submitter | 1.6 | 25 | yes |
| ai-bom.cdx.json | Vulnetix/pix-ai-coding-assistant | 1.7 | 2 | yes |
| cbom.cdx.json | Vulnetix/vdb-cyclonedx | 1.7 | 20 | yes |

### cyclonedx cases

| Case | Operation | Status | Schema | Latency | Verdict |
|---|---|---:|---|---:|---|
| 25 further BOM document(s) were not downloaded (limit 25) | `-` | - | - | - | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/osm-submitter | `artifactDownload` | 200 | yes | 128.88 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/vdb-sca-match | `artifactDownload` | 200 | **no** | 602.30 ms | **FAIL** |
| download and validate AI Bill of Materials of Vulnetix/headshot | `artifactDownload` | 200 | yes | 130.92 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/vdb-sca-match | `artifactDownload` | 200 | **no** | 514.83 ms | **FAIL** |
| download and validate Cryptography Bill of Materials of Vulnetix/sca-manifest-fixtures | `artifactDownload` | 200 | yes | 170.97 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 181.89 ms | pass |
| download and validate Vulnetix SCA Software Bill of Materials of Vulnetix/opa-cds-aws-tf | `artifactDownload` | 200 | yes | 245.01 ms | pass |
| download and validate Vulnetix SCA Software Bill of Materials of Vulnetix/opa-cigna-tf | `artifactDownload` | 200 | yes | 341.11 ms | pass |
| download and validate Vulnetix SCA Software Bill of Materials of Vulnetix/community-rules | `artifactDownload` | 200 | yes | 522.79 ms | pass |
| download and validate sbom.cdx.json of Vulnetix/vdb-cyclonedx | `artifactDownload` | 200 | yes | 497.26 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/vdb-api | `artifactDownload` | 200 | **no** | 470.24 ms | **FAIL** |
| download and validate AI Bill of Materials of Vulnetix/cli | `artifactDownload` | 200 | yes | 128.77 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/headshot | `artifactDownload` | 200 | yes | 128.89 ms | pass |
| download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/python-ssvc | `artifactDownload` | 200 | yes | 513.58 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/python-ssvc | `artifactDownload` | 200 | yes | 886.82 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/s3-queue-gui | `artifactDownload` | 200 | yes | 171.41 ms | pass |
| download and validate vulnetix-containers Software Bill of Materials of Vulnetix/vdb-site | `artifactDownload` | 200 | yes | 678.11 ms | pass |
| download and validate Cryptography Bill of Materials of Vulnetix/vdb-api | `artifactDownload` | 200 | yes | 830.86 ms | pass |
| download and validate AI Bill of Materials of Vulnetix/sca-manifest-fixtures | `artifactDownload` | 200 | yes | 128.95 ms | pass |
| download and validate cbom.cdx.json of Vulnetix/ai-firewall | `artifactDownload` | 200 | yes | 516.40 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/vdb-api | `artifactDownload` | 200 | **no** | 346.21 ms | **FAIL** |
| download and validate sbom.cdx.json of Vulnetix/github-runner-aws | `artifactDownload` | 200 | yes | 604.20 ms | pass |
| download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/osm-submitter | `artifactDownload` | 200 | yes | 596.81 ms | pass |
| download and validate ai-bom.cdx.json of Vulnetix/pix-ai-coding-assistant | `artifactDownload` | 200 | yes | 757.86 ms | pass |
| download and validate cbom.cdx.json of Vulnetix/vdb-cyclonedx | `artifactDownload` | 200 | yes | 985.53 ms | pass |

#### Detail

**download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/vdb-sca-match**: `GET https://www.vulnetix.com/tea/v1/artifact/0ed4d75f-281e-49d5-827c-0fafa0f13c09/1/download`

- CycloneDX 1.6: /vulnerabilities/0/analysis/response: at '/vulnerabilities/0/analysis/response': got string, want array
- CycloneDX 1.6: /vulnerabilities/1/analysis/response: at '/vulnerabilities/1/analysis/response': got string, want array
- evidence: `responses/cyclonedx/0002-get-download-and-validate-vulnetix-sca-monitor-software-bill-of-materials-of.meta.json`

**download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/vdb-sca-match**: `GET https://www.vulnetix.com/tea/v1/artifact/1bc0bfc1-cb2f-4f12-9301-0a657c3e7161/1/download`

- CycloneDX 1.7: /components: at '/components': items at 0 and 1 are equal
- CycloneDX 1.7: /vulnerabilities/0/analysis/response: at '/vulnerabilities/0/analysis/response': got string, want array
- CycloneDX 1.7: /vulnerabilities/1/analysis/response: at '/vulnerabilities/1/analysis/response': got string, want array
- evidence: `responses/cyclonedx/0004-get-download-and-validate-vulnetix-sca-vulnerability-exploitability-exchange.meta.json`

**download and validate Vulnetix SCA Vulnerability Exploitability eXchange of Vulnetix/vdb-api**: `GET https://www.vulnetix.com/tea/v1/artifact/64329f9e-8918-4a63-aecd-e26f716d20d9/1/download`

- CycloneDX 1.7: /vulnerabilities/0/analysis/response: at '/vulnerabilities/0/analysis/response': got string, want array
- CycloneDX 1.7: /vulnerabilities/1/analysis/response: at '/vulnerabilities/1/analysis/response': got string, want array
- CycloneDX 1.7: /vulnerabilities/2/analysis/response: at '/vulnerabilities/2/analysis/response': got string, want array
- CycloneDX 1.7: /vulnerabilities/4/analysis/state: at '/vulnerabilities/4/analysis/state': value must be one of 'resolved', 'resolved_with_pedigree', 'exploitable', 'in_triage', 'false_positive', 'not_affected'
- CycloneDX 1.7: /components: at '/components': items at 3 and 4 are equal
- evidence: `responses/cyclonedx/0011-get-download-and-validate-vulnetix-sca-vulnerability-exploitability-exchange.meta.json`

**download and validate Vulnetix SCA Monitor Software Bill of Materials of Vulnetix/vdb-api**: `GET https://www.vulnetix.com/tea/v1/artifact/8ed20417-3277-43d5-b7f6-d53e11d117a9/1/download`

- CycloneDX 1.6: /vulnerabilities/1/analysis/response: at '/vulnerabilities/1/analysis/response': got string, want array
- CycloneDX 1.6: /vulnerabilities/2/analysis/response: at '/vulnerabilities/2/analysis/response': got string, want array
- CycloneDX 1.6: /vulnerabilities/4/analysis/state: at '/vulnerabilities/4/analysis/state': value must be one of 'resolved', 'resolved_with_pedigree', 'exploitable', 'in_triage', 'false_positive', 'not_affected'
- evidence: `responses/cyclonedx/0021-get-download-and-validate-vulnetix-sca-monitor-software-bill-of-materials-of.meta.json`


[Back to the summary](../)
