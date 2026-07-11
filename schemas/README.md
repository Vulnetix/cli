# Schemas

Authoring home for the JSON Schemas the CLI publishes and validates against. `just sync-schemas` copies this
directory into `internal/analyze/schemas/` so `go:embed` has a package-local copy; this directory stays the
source of truth and is what gets published at a stable URL.

Edit here, never in `internal/analyze/schemas/`. A drift check runs in CI.

## Ours

| File | `$id` | Purpose |
|---|---|---|
| `vulnetix-analyze-report.schema.json` | `https://vulnetix.com/schemas/vulnetix-analyze-report.schema.json` | Output of `vulnetix analyze`: the repository's tech-stack graph, its cross-repo join keys, and every metric with the evidence behind it. |

The report schema `$ref`s the vendored schemas below rather than restating them, so evidence is emitted in
the open format that already exists for it: file-and-line findings are SARIF, security assertions are
OpenVEX, the component inventory is CycloneDX, license evidence is SPDX, repository-practice checks are
OpenSSF Scorecard. Only evidence with no established open format (commits, contributors, issues, pull
requests, graph elements) is carried as an inline record.

## Vendored

Fetched verbatim from upstream. Do not hand-edit — re-fetch from the URL below and note the change.

| File | Upstream | License |
|---|---|---|
| `third_party/sarif-2.1.0.schema.json` | https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json | OASIS IPR Policy |
| `third_party/openvex-0.2.0.schema.json` | https://raw.githubusercontent.com/openvex/spec/main/openvex_json_schema.json | Apache-2.0 |
| `third_party/cyclonedx-1.7.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/bom-1.7.schema.json | Apache-2.0 |
| `third_party/cyclonedx-spdx.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/spdx.schema.json | Apache-2.0 |
| `third_party/cyclonedx-jsf-0.82.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/jsf-0.82.schema.json | Apache-2.0 |
| `third_party/cyclonedx-cryptography-defs.schema.json` | https://raw.githubusercontent.com/CycloneDX/specification/master/schema/cryptography-defs.schema.json | Apache-2.0 |
| `third_party/spdx-2.3.schema.json` | https://raw.githubusercontent.com/spdx/spdx-spec/support/v2.3/schemas/spdx-schema.json | CC-BY-3.0 |

The three `cyclonedx-*` companions are not directly referenced by the report schema — CycloneDX's own
`bom-1.7.schema.json` `$ref`s them by relative path, so they must be registered as resources under
`http://cyclonedx.org/schema/` for the BOM schema to compile at all.

### Not vendored, because upstream does not publish one

`third_party/ossf-scorecard-result.schema.json` is **authored by us**, transcribed from the Go types in
[`ossf/scorecard`](https://github.com/ossf/scorecard) (`pkg/scorecard`, the v2 JSON result). OpenSSF ships no
JSON Schema for its own output. Keep this in step with upstream when Scorecard adds fields; a Scorecard result
that fails to validate against it means this file is stale, not that the result is wrong.

## Mixed drafts

The vendored schemas do not agree on a draft — SARIF is draft-04, CycloneDX and SPDX are draft-07, OpenVEX and
ours are 2020-12. This is fine: each resource declares its own `$schema` and `santhosh-tekuri/jsonschema/v6`
resolves each under its own dialect. Do not "fix" this by rewriting a vendored schema's `$schema` field.
