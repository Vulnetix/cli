# PLAN — `vdb-cyclonedx`

Pure-stdlib CycloneDX SBOM parser supporting spec versions **1.2 through 1.7**, **extracted
byte-for-byte** (behavior-preserving) from the proven parser in
`vdb-api-cyclonedx-uploads/internal/processor/{cyclonedx.go, parity.go, purl.go}`.

This is a **refactor-and-promote, not a rewrite**. The upload pipeline currently depends on this
exact parser; extraction must not change its behavior. After extraction,
`vdb-api-cyclonedx-uploads` and the new `vdb-sca-monitor` both import this single module, so SBOMs
are parsed identically everywhere.

## Why this module exists
- `vdb-sca-monitor`'s consumer downloads a reference scan's CycloneDX SBOM from S3 and parses it as
  the primary dependency source. It must parse exactly what the upload pipeline produced.
- Single-sourcing the parser stops the two repos from drifting on CycloneDX version handling.
- It is consumed as a **sibling Go module** via `replace github.com/Vulnetix/vdb-cyclonedx =>
  ../vdb-cyclonedx`, cloned at container-build time — the same pattern `vdb-api` uses for
  `github.com/Vulnetix/ietf-crit-spec` (`vdb-api/AGENTS.md` → "Local replace directive").

## go.mod
```
module github.com/Vulnetix/vdb-cyclonedx
go 1.25.0
// no require block — standard library only (encoding/json, bytes, strings)
```

## File tree
```
vdb-cyclonedx/
├── go.mod
├── README.md                 // supported spec versions, usage, provenance
├── PLAN.md                   // this file
├── cyclonedx.go              // types + ParseCDX + ExtractEcosystem + ExtractLicense
├── tools.go                  // CDXTools/CDXDependency version-tolerant UnmarshalJSON
├── graph.go                  // BOM dependency-graph helpers (from parity.go): BFS root→leaf
├── purl.go                   // ParsePurl: PURL → (ecosystem, fullName/namespace, version)
├── cyclonedx_test.go         // table tests across spec versions 1.2–1.7
└── graph_test.go             // introduced-via path reconstruction tests
```

## Public API (moved verbatim from `cyclonedx.go:9-200`, package renamed to `cyclonedx`)
```go
package cyclonedx

type CDXOrg struct{ Name string }
type CDXComponent struct {
    BomRef, Type, Name, Version, Purl, Group, Scope string
    Author, Publisher, Description                  string
    Manufacturer, Supplier                          *CDXOrg
    Hashes             []struct{ Alg, Content string }
    ExternalReferences []struct{ URL, Type string }
    Properties         []struct{ Name, Value string }
    Licenses           []struct{ License struct{ ID, Name string } }
}
type CDXVulnRating struct{ Score float64; Severity, Method, Vector string }
type CDXVulnerability struct {
    BomRef, ID                                      string
    Source                                          *struct{ Name, URL string }
    Ratings                                         []CDXVulnRating
    CWEs                                            []int
    Description, Recommendation, Published, Updated string
    Affects                                         []struct{ Ref string }
}
type CDXMetadata struct { Timestamp string; Component *CDXComponent; Tools *CDXTools; /* …authors,supplier… */ }
type CDXTools     struct { Components []CDXComponent }          // custom UnmarshalJSON (tools.go)
type CDXDependency struct { Ref string; DependsOn []string }    // custom UnmarshalJSON (tools.go)
type CDXBom struct {
    BomFormat, SpecVersion, SerialNumber string
    Metadata        CDXMetadata
    Components      []CDXComponent
    Dependencies    []CDXDependency
    Vulnerabilities []CDXVulnerability
}

func ParseCDX(data []byte) (*CDXBom, error)   // unchanged
func ExtractEcosystem(purl string) string     // pkg:<type>/… → "<type>"
func ExtractLicense(comp CDXComponent) string // first license id/name
func ParsePurl(purl string) (ecosystem, fullName, version string) // from internal/processor/purl.go
```

## What delivers 1.2–1.7 (`tools.go`) — moves unchanged (`cyclonedx.go:95-159`)
The two custom `UnmarshalJSON` methods are the only spec-version-specific logic; the rest of the
schema is additive across 1.2→1.7 so the flat structs parse every version:
- `CDXTools.UnmarshalJSON` — accepts both `metadata.tools` shapes: **1.2–1.4 array form**
  `[{vendor,name,version,hashes}]` (backfills legacy `vendor` → `Publisher`) and **1.5–1.7 object
  form** `{components:[…], services:[…]}`. Returns `nil` on anything else (tool metadata is
  best-effort; a malformed `tools` must never fail BOM ingestion).
- `CDXDependency.UnmarshalJSON` — coalesces **1.4+ `dependsOn`** and **1.2–1.3 `dependencies`**
  into one `DependsOn` field.

## BOM-graph helpers (`graph.go`, from `parity.go:133-176`)
Dependency-path reconstruction: build the `dependsOn` adjacency list from `CDXBom.Dependencies`,
BFS from the root component (`metadata.component.bom-ref`) to a target, return the shortest path
(root-excluded). Feeds `FindingIntroducedVia`.
```go
func BuildGraph(bom *CDXBom) *Graph
func (g *Graph) PathTo(rootRef, targetRef string) []string // shortest root→target, root excluded
```

## Dropped (do NOT move)
`SemverSortDesc`, `compareSemver`, `semverParts` (`cyclonedx.go:202-256`) — version ordering is
owned by `vdb-sca-match/version`. Their only call site (fix-version sorting) is repointed to the
matcher.

## Tests (`cyclonedx_test.go`)
Extend the existing `cyclonedx_tools_test.go` (already covers 1.2–1.5) to **1.6 and 1.7**:
- `tools` array form (1.2–1.4) and object form (1.5–1.7) both populate `CDXTools.Components`.
- `dependencies[].dependsOn` (1.4+) and `dependencies[].dependencies` (1.2–1.3) both populate `DependsOn`.
- Real 1.6 and 1.7 fixtures parse without error, yield expected components/vulns.
- Malformed `tools`/`dependencies` → no error, empty slice (fail-soft contract preserved).

## Adoption in `vdb-api-cyclonedx-uploads` (behavior-identical refactor)
1. Delete `internal/processor/cyclonedx.go` + `purl.go` + graph parts of `parity.go`; import this module.
2. `go.mod`: `require github.com/Vulnetix/vdb-cyclonedx v0.1.0` +
   `replace github.com/Vulnetix/vdb-cyclonedx => ../vdb-cyclonedx`.
3. Containerfile: `git clone …/vdb-cyclonedx.git /vdb-cyclonedx` before `go build` (WORKDIR `/app`
   → `../vdb-cyclonedx` resolves to `/vdb-cyclonedx`).
4. Run the repo's tests + a CDX upload smoke test → confirm zero behavioral drift.

## Build / verification
`go build ./...` → `go test ./...` (1.2–1.7 matrix green). Tag `v0.1.0` (sibling builds rely on
`replace`; tags help if ever published). Pure stdlib — no `go mod tidy` surprises.

## Source files to extract from
- `vdb-api-cyclonedx-uploads/internal/processor/cyclonedx.go` (types, `ParseCDX`, extractors, the
  two `UnmarshalJSON`s; drop `compareSemver`/`semverParts`/`SemverSortDesc`).
- `vdb-api-cyclonedx-uploads/internal/processor/parity.go` (BOM-graph BFS path reconstruction).
- `vdb-api-cyclonedx-uploads/internal/processor/purl.go` (`parsePurl`).
- `vdb-api-cyclonedx-uploads/internal/processor/cyclonedx_tools_test.go` (existing 1.2–1.5 tests to
  carry over + extend).

## Companion plans
- `vdb-sca-match/PLAN.md` — the matching engine module.
- `~/.claude/plans/create-a-new-repo-distributed-wolf.md` and `Vulnetix/PLAN.md` — the
  `vdb-sca-monitor` service that consumes both modules.
