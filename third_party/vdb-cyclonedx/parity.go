package cyclonedx

import (
	"fmt"
	"strings"
)

// License is a license declared in the SBOM (SPDX id and/or name).
type License struct {
	SPDXID string
	Name   string
}

// ToolMeta describes the tool that generated the SBOM.
type ToolMeta struct {
	SpecVersion string
	ToolName    string
	ToolVersion string
	ToolVendor  string
	ToolHash    string
}

// IntroducedVia is one dependency path leading to a vulnerable component.
type IntroducedVia struct {
	PathIndex      int
	PathLength     int
	PackageManager string
	ManifestFile   string
	DependencyPath string
	DependencyKeys []string
}

// registryURLForEcosystem maps an ecosystem to its canonical package registry.
// Returns "" when unknown.
func RegistryURLForEcosystem(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "https://registry.npmjs.org"
	case "pypi", "pip", "python":
		return "https://pypi.org"
	case "go", "golang":
		return "https://proxy.golang.org"
	case "cargo", "crates", "rust":
		return "https://crates.io"
	case "rubygems", "gem":
		return "https://rubygems.org"
	case "maven", "java":
		return "https://repo.maven.apache.org"
	case "composer", "packagist", "php":
		return "https://packagist.org"
	case "nuget", ".net":
		return "https://www.nuget.org"
	}
	return ""
}

// AdvisoryURL returns the NVD detail URL for a CVE id.
func AdvisoryURL(cveID string) string {
	if cveID == "" {
		return ""
	}
	return "https://nvd.nist.gov/vuln/detail/" + cveID
}

// ComponentKey mirrors the Dependency primary key built in buildDependencyRows
// (cdxId:name:version) so FindingIntroducedVia.dependencyKeys references the
// same rows persisted by BulkInsertDependencies.
func ComponentKey(cdxID string, c *CDXComponent) string {
	return fmt.Sprintf("%s:%s:%s", cdxID, c.Name, c.Version)
}

// ExtractLicenses collects the distinct licenses declared across all components
// and the BOM's primary component.
func ExtractLicenses(bom *CDXBom) []License {
	seen := map[string]bool{}
	var out []License
	add := func(comp CDXComponent) {
		for _, l := range comp.Licenses {
			id := strings.TrimSpace(l.License.ID)
			name := strings.TrimSpace(l.License.Name)
			if id == "" && name == "" {
				continue
			}
			dedup := id + "|" + name
			if seen[dedup] {
				continue
			}
			seen[dedup] = true
			out = append(out, License{SPDXID: id, Name: name})
		}
	}
	if bom.Metadata.Component != nil {
		add(*bom.Metadata.Component)
	}
	for _, c := range bom.Components {
		add(c)
	}
	return out
}

// ExtractToolMeta pulls the generating tool's identity from metadata.tools
// (CycloneDX 1.5+ tools.components). Returns zero-value fields when the BOM
// declares no tool.
func ExtractToolMeta(bom *CDXBom) ToolMeta {
	row := ToolMeta{SpecVersion: bom.SpecVersion}
	if bom.Metadata.Tools == nil || len(bom.Metadata.Tools.Components) == 0 {
		return row
	}
	t := bom.Metadata.Tools.Components[0]
	row.ToolName = t.Name
	row.ToolVersion = t.Version
	switch {
	case t.Publisher != "":
		row.ToolVendor = t.Publisher
	case t.Supplier != nil && t.Supplier.Name != "":
		row.ToolVendor = t.Supplier.Name
	case t.Author != "":
		row.ToolVendor = t.Author
	}
	for _, h := range t.Hashes {
		if h.Content != "" {
			row.ToolHash = h.Content
			break
		}
	}
	return row
}

// DistinctEcosystems returns the set of ecosystems seen across component PURLs.
func DistinctEcosystems(bom *CDXBom) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range bom.Components {
		eco := ExtractEcosystem(c.Purl)
		if eco == "" || seen[eco] {
			continue
		}
		seen[eco] = true
		out = append(out, eco)
	}
	return out
}

// BuildIntroducedViaFromBOM derives a single dependency path (shortest, from the
// BOM's primary component to the vulnerable component) from the BOM's
// dependencies[] adjacency. Returns nil when no path can be built.
//
// packageManager is the ecosystem (or "unknown") and manifestFile is "sbom",
// since a plain SBOM upload has neither a real package manager nor a manifest.
func BuildIntroducedViaFromBOM(bom *CDXBom, cdxID, targetRef, ecosystem string, compByRef map[string]*CDXComponent) []IntroducedVia {
	target := compByRef[targetRef]
	if targetRef == "" || target == nil {
		return nil
	}
	pm := ecosystem
	if pm == "" {
		pm = "unknown"
	}

	path := ShortestDepPath(bom, targetRef)
	if len(path) == 0 {
		// No graph path — record the component as its own (direct) origin so the
		// finding still carries an introducedVia row.
		path = []string{targetRef}
	}

	names := make([]string, 0, len(path))
	keys := make([]string, 0, len(path))
	for _, ref := range path {
		c := compByRef[ref]
		if c == nil {
			continue
		}
		label := c.Name
		if c.Version != "" {
			label += "@" + c.Version
		}
		names = append(names, label)
		keys = append(keys, ComponentKey(cdxID, c))
	}
	if len(keys) == 0 {
		return nil
	}

	return []IntroducedVia{{
		PathIndex:      0,
		PathLength:     len(keys),
		PackageManager: pm,
		ManifestFile:   "sbom",
		DependencyPath: strings.Join(names, " > "),
		DependencyKeys: keys,
	}}
}

// ShortestDepPath returns the bom-ref chain from the BOM's primary component to
// targetRef (inclusive) using BFS over dependencies[].dependsOn edges. The root
// app component itself is excluded from the returned path (it is not a
// Dependency row). Returns nil when no path exists.
func ShortestDepPath(bom *CDXBom, targetRef string) []string {
	if bom.Metadata.Component == nil || bom.Metadata.Component.BomRef == "" {
		return nil
	}
	root := bom.Metadata.Component.BomRef

	adj := make(map[string][]string, len(bom.Dependencies))
	for _, d := range bom.Dependencies {
		adj[d.Ref] = d.DependsOn
	}

	prev := map[string]string{}
	visited := map[string]bool{root: true}
	queue := []string{root}
	found := false
	for len(queue) > 0 && !found {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range adj[cur] {
			if visited[next] {
				continue
			}
			visited[next] = true
			prev[next] = cur
			if next == targetRef {
				found = true
				break
			}
			queue = append(queue, next)
		}
	}
	if !found {
		return nil
	}

	// Reconstruct root→target, then drop the root app component.
	var rev []string
	for at := targetRef; at != ""; at = prev[at] {
		rev = append(rev, at)
		if at == root {
			break
		}
	}
	// rev is target→root; reverse and strip the leading root.
	var path []string
	for i := len(rev) - 1; i >= 0; i-- {
		if rev[i] == root {
			continue
		}
		path = append(path, rev[i])
	}
	return path
}
