# vdb-cyclonedx

CycloneDX SBOM parser and schema validator for Go, supporting spec versions **1.2 through 1.7** plus
the official **2.0 development schema**.

Extracted (behavior-preserving) from `vdb-api-cyclonedx-uploads`'s internal parser so it can be
shared across Vulnetix services — currently `vdb-api-cyclonedx-uploads` (SBOM upload pipeline) and
`vdb-sca-monitor` (scheduled SCA re-evaluation).

```go
import "github.com/Vulnetix/vdb-cyclonedx"

bom, err := cyclonedx.ParseCDX(data)         // validates and parses 1.2–1.7 and 2.0-dev
g := cyclonedx.BuildGraph(bom)               // dependency graph
path := g.PathTo(rootRef, vulnerableRef)     // introduced-via chain
```

Consumed as a sibling module via `replace github.com/Vulnetix/vdb-cyclonedx => ../vdb-cyclonedx`
(the same pattern `vdb-api` uses for `ietf-crit-spec`), cloned at container-build time.

See [PLAN.md](./PLAN.md) for the full design and extraction plan.

## Status

Scaffold + plan. Implementation extracts `internal/processor/{cyclonedx,parity,purl}.go` from
`vdb-api-cyclonedx-uploads`, with embedded official JSON schemas for validation.
