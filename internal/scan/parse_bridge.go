package scan

// Manifest/lockfile parsing lives in the shared github.com/Vulnetix/vdb-sca-match/parse
// module so the vdb-api server and this CLI parse manifests identically (a
// manifest uploaded to POST /v2/scan/manifest keys the same vulnerability rows
// as a local `vdb sca` run). This file re-exports the parse surface the rest of
// the scan package and the cmd/ layer depend on, so their call sites stay
// `scan.*` and unchanged.

import (
	"github.com/Vulnetix/vdb-sca-match/parse"
)

// ── Types ──────────────────────────────────────────────────────────────────

// ScopedPackage is a parsed dependency with scope/provenance information.
type ScopedPackage = parse.ScopedPackage

// PackageChecksum is one integrity hash extracted from a lock file.
type PackageChecksum = parse.PackageChecksum

// RegistryEndpoint is a package registry discovered from a registry-config file.
type RegistryEndpoint = parse.RegistryEndpoint

// ── Scope constants (native package-manager terminology) ───────────────────

const (
	ScopeProduction  = parse.ScopeProduction
	ScopeDevelopment = parse.ScopeDevelopment
	ScopeTest        = parse.ScopeTest
	ScopePeer        = parse.ScopePeer
	ScopeOptional    = parse.ScopeOptional
	ScopeProvided    = parse.ScopeProvided
	ScopeRuntime     = parse.ScopeRuntime
	ScopeSystem      = parse.ScopeSystem
)

// ── Discovery-source provenance constants ──────────────────────────────────

const (
	SourceTypeManifest  = parse.SourceTypeManifest
	SourceTypeInstalled = parse.SourceTypeInstalled
)

// ── Function re-exports ────────────────────────────────────────────────────

// ScopeIcon returns a display icon for a scope category.
func ScopeIcon(scope string) string { return parse.ScopeIcon(scope) }

// ParseManifestWithScope reads a manifest file and returns scoped packages.
func ParseManifestWithScope(filePath, manifestType string) ([]ScopedPackage, error) {
	return parse.ParseManifestWithScope(filePath, manifestType)
}

// ParseRegistryConfig parses a registry-config file into its endpoints.
func ParseRegistryConfig(filePath, ecosystem string) []RegistryEndpoint {
	return parse.ParseRegistryConfig(filePath, ecosystem)
}

// SummarizeRegistryConfigs parses every registry-config file among the detected
// files and returns the endpoints found. Kept here (not in the parse module)
// because it depends on the CLI's DetectedFile detection layer.
func SummarizeRegistryConfigs(files []DetectedFile) []RegistryEndpoint {
	var out []RegistryEndpoint
	for _, f := range files {
		if f.ManifestInfo == nil || f.ManifestInfo.Language != "registry-config" {
			continue
		}
		out = append(out, parse.ParseRegistryConfig(f.Path, f.ManifestInfo.Ecosystem)...)
	}
	return out
}
