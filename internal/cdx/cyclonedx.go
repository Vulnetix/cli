package cdx

import (
	"fmt"
	"strings"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/scan"
)

// ScanContext carries optional environment-enrichment data passed to BOM builders.
// All fields are optional; nil pointers are silently ignored.
type ScanContext struct {
	// Git is the git repository context collected from the scanned directory.
	Git *gitctx.GitContext
	// System is the host/process environment at scan time.
	System *gitctx.SystemInfo
	// ToolVersion is the version string injected at build time (e.g. "1.2.3").
	ToolVersion string
	// ToolName is the CycloneDX metadata tool component name. Defaults to
	// vulnetix-sca for backward compatibility.
	ToolName string
	// Manufacturer is the organization that created the BOM — the one running
	// this scan, resolved by ResolveManufacturer. Nil when nothing resolved it,
	// which leaves metadata.manufacturer absent rather than guessed.
	Manufacturer *OrganizationalEntity
	// Phases are the lifecycle stages at which this pass captured its data,
	// derived by DerivePhases from what the pass actually read.
	Phases []LifecyclePhase
}

// AnalysisForStateChange builds a CycloneDX VEX analysis block for an
// auto-generated finding state transition. status is the Vulnetix finding
// status (e.g. "fixed", "under_investigation"); detail carries free-text
// context. Returns nil for statuses that carry no analysis block.
//
// A "fixed" finding maps to state=resolved with response=["update"] — "update"
// is an impactAnalysisResponse value (the remediation taken), NOT a
// justification. justification (impactAnalysisJustification) is reserved for
// state=not_affected and would fail CycloneDX schema validation here.
func AnalysisForStateChange(status, detail string) *Analysis {
	switch status {
	case "fixed":
		return &Analysis{State: "resolved", Response: []string{"update"}, Detail: detail}
	case "under_investigation":
		return &Analysis{State: "in_triage", Detail: detail}
	}
	return nil
}

// ApplyVEXAnalysis folds auto-generated VEX entries into a BOM.
//
// When the BOM already carries a vulnerability with the same id — the usual case
// for a finding that a previous run recorded and this run resolved — the entry's
// analysis and properties are attached to it. Appending a second entry under the
// same id would leave the BOM asserting both that the vulnerability is open and
// that it is resolved.
//
// Call this after MergeBOMs, so that vulnerabilities carried over from the
// previous BOM on disk are visible to the id lookup.
func ApplyVEXAnalysis(bom *BOM, vexEntries []Vulnerability) {
	if bom == nil || len(vexEntries) == 0 {
		return
	}
	index := make(map[string]int, len(bom.Vulnerabilities))
	for i, v := range bom.Vulnerabilities {
		if _, seen := index[v.ID]; !seen {
			index[v.ID] = i
		}
	}
	for _, entry := range vexEntries {
		i, found := index[entry.ID]
		if !found {
			index[entry.ID] = len(bom.Vulnerabilities)
			bom.Vulnerabilities = append(bom.Vulnerabilities, entry)
			continue
		}
		target := &bom.Vulnerabilities[i]
		if entry.Analysis != nil {
			target.Analysis = entry.Analysis
		}
		existing := make(map[string]bool, len(target.Properties))
		for _, p := range target.Properties {
			existing[p.Name] = true
		}
		for _, p := range entry.Properties {
			if !existing[p.Name] {
				target.Properties = append(target.Properties, p)
			}
		}
	}
}

// scoreTypeToMethod maps internal score type names to CycloneDX method identifiers.
var scoreTypeToMethod = map[string]string{
	"epss":          "other",
	"coalition_ess": "other",
	"cvssv4":        "CVSSv4",
	"cvss4":         "CVSSv4",
	"cvssv3.1":      "CVSSv31",
	"cvss3.1":       "CVSSv31",
	"cvssv3.0":      "CVSSv3",
	"cvss3.0":       "CVSSv3",
	"cvss3":         "CVSSv3",
	"cvssv3":        "CVSSv3",
	"cvssv2":        "CVSSv2",
	"cvss2":         "CVSSv2",
	"cvssv2.0":      "CVSSv2",
}

// vulnSourceForFind determines the vulnerability source name for the local scan path
// (VulnFinding). When the finding's Source field is set, it is used as the name.
// The URL is always https://www.vulnetix.com/vdb.
func vulnSourceForFind(f scan.VulnFinding) *Source {
	if f.Source == "vulnetix" {
		return &Source{Name: "Vulnetix VDB", URL: "https://www.vulnetix.com/vdb"}
	}
	if f.Source != "" {
		return &Source{Name: f.Source, URL: "https://www.vulnetix.com/vdb"}
	}
	return &Source{Name: "Vulnetix VDB", URL: "https://www.vulnetix.com/vdb"}
}

// ---------------------------------------------------------------------------
// Metadata enrichment
// ---------------------------------------------------------------------------

// populateMetadataFromContext enriches a BOM Metadata block with git-repository
// and host-environment data from the provided ScanContext.
//
// Git context is captured in metadata.component (the project being described)
// using externalReferences for VCS URLs and properties for detailed git state.
// Host environment is captured in metadata.properties.
func populateMetadataFromContext(meta *Metadata, ctx *ScanContext) {
	if ctx == nil {
		return
	}

	// ── git context → metadata.component ─────────────────────────────────
	if g := ctx.Git; g != nil {
		projName := GitProjectName(g)
		projVersion := GitProjectVersion(g)

		comp := &Component{
			Type:        "application",
			BOMRef:      "urn:project",
			Name:        projName,
			Version:     projVersion,
			Description: "Source code repository",
		}

		// VCS external references (one per remote URL).
		// Normalize SSH git URLs to HTTPS so the value is a valid iri-reference.
		for _, u := range g.RemoteURLs {
			comp.ExternalReferences = append(comp.ExternalReferences, ExternalReference{
				Type: "vcs",
				URL:  normalizeVCSURL(u),
			})
		}

		// Detailed git state as component properties.
		if g.CurrentBranch != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:git/branch", g.CurrentBranch))
		}
		if g.CurrentCommit != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:git/commit", g.CurrentCommit))
		}
		if g.HeadCommitTimestamp != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:git/commit-timestamp", g.HeadCommitTimestamp))
		}
		if g.HeadCommitMessage != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:git/commit-message", g.HeadCommitMessage))
		}
		if g.HeadCommitAuthor != "" {
			v := g.HeadCommitAuthor
			if g.HeadCommitEmail != "" {
				v += " <" + g.HeadCommitEmail + ">"
			}
			comp.Properties = append(comp.Properties, prop("vulnetix:git/commit-author", v))
		}
		if len(g.HeadTags) > 0 {
			comp.Properties = append(comp.Properties, prop("vulnetix:git/tags", strings.Join(g.HeadTags, ", ")))
		}
		comp.Properties = append(comp.Properties, prop("vulnetix:git/dirty", boolStr(g.IsDirty)))
		comp.Properties = append(comp.Properties, prop("vulnetix:git/is-worktree", boolStr(g.IsWorktree)))
		if g.RepoRootPath != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:git/repo-root", g.RepoRootPath))
		}

		// Recent committers as CDX 1.6 component authors.
		for _, c := range g.RecentCommitters {
			comp.Authors = append(comp.Authors, OrganizationalContact{
				Name:  c.Name,
				Email: c.Email,
			})
		}

		meta.Component = comp
	}

	// ── host / process environment → metadata.properties ─────────────────
	if s := ctx.System; s != nil {
		if s.Hostname != "" {
			meta.Properties = append(meta.Properties, prop("vulnetix:env/hostname", s.Hostname))
		}
		if s.Shell != "" {
			meta.Properties = append(meta.Properties, prop("vulnetix:env/shell", s.Shell))
		}
		if s.OS != "" {
			meta.Properties = append(meta.Properties, prop("vulnetix:env/os", s.OS))
		}
		if s.Arch != "" {
			meta.Properties = append(meta.Properties, prop("vulnetix:env/arch", s.Arch))
		}
		if s.Username != "" {
			meta.Properties = append(meta.Properties, prop("vulnetix:env/user", s.Username))
		}
	}
}

// GitProjectName derives a human-readable project name from the git context.
// Priority: first remote URL path → repo root directory name → "unknown".
func GitProjectName(g *gitctx.GitContext) string {
	if len(g.RemoteURLs) > 0 {
		if name := extractRepoName(g.RemoteURLs[0]); name != "" {
			return name
		}
	}
	if g.RepoRootPath != "" {
		if base := lastPathComponent(g.RepoRootPath); base != "" {
			return base
		}
	}
	return "unknown"
}

// GitProjectVersion returns the best available version string for the project.
// Priority: first tag at HEAD → short commit SHA → empty.
func GitProjectVersion(g *gitctx.GitContext) string {
	if len(g.HeadTags) > 0 {
		return g.HeadTags[0]
	}
	if len(g.CurrentCommit) >= 8 {
		return g.CurrentCommit[:8]
	}
	return g.CurrentCommit
}

// normalizeVCSURL converts an SSH git remote URL to its HTTPS equivalent so
// the result is a valid IRI-reference as required by CycloneDX schemas.
//
//	git@github.com:owner/repo.git  →  https://github.com/owner/repo
//	https://github.com/owner/repo  →  https://github.com/owner/repo (unchanged)
func normalizeVCSURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	// Already an HTTP/HTTPS URL — just strip trailing .git for cleanliness.
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		return strings.TrimSuffix(rawURL, ".git")
	}
	// SSH SCP-style: git@host:path/to/repo.git
	if idx := strings.IndexByte(rawURL, ':'); idx >= 0 {
		// Extract host (strip any user@ prefix)
		hostPart := rawURL[:idx]
		if at := strings.IndexByte(hostPart, '@'); at >= 0 {
			hostPart = hostPart[at+1:]
		}
		pathPart := strings.TrimSuffix(rawURL[idx+1:], ".git")
		return "https://" + hostPart + "/" + pathPart
	}
	return rawURL
}

// extractRepoName parses a VCS URL (SSH or HTTPS) and returns "owner/repo".
//
//	git@github.com:owner/repo.git  →  owner/repo
//	https://github.com/owner/repo  →  owner/repo
func extractRepoName(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}
	// SSH form: git@host:path
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		if idx := strings.IndexByte(rawURL, ':'); idx >= 0 {
			path := rawURL[idx+1:]
			path = strings.TrimSuffix(path, ".git")
			return path
		}
	}
	// HTTPS form
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest := rawURL[idx+3:]
		slash := strings.IndexByte(rest, '/')
		if slash >= 0 {
			path := rest[slash+1:]
			path = strings.TrimSuffix(path, ".git")
			path = strings.TrimSuffix(path, "/")
			return path
		}
	}
	return ""
}

// lastPathComponent returns the last element of a file-system path.
func lastPathComponent(p string) string {
	p = strings.TrimRight(p, "/\\")
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// prop is a convenience constructor for Property.
func prop(name, value string) Property { return Property{Name: name, Value: value} }

// boolStr converts a bool to the CycloneDX conventional string form.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// FormatSpec returns the format string for CLI display.
func FormatSpec(specVersion string) string {
	return fmt.Sprintf("CycloneDX %s", specVersion)
}

// ValidSpecVersions returns the list of supported CycloneDX spec versions.
func ValidSpecVersions() []string {
	return []string{"1.2", "1.3", "1.4", "1.5", "1.6", "1.7"}
}

// NormalizeFormat maps user-facing format names to spec versions or output type.
// Returns (specVersion, isRawJSON).
func NormalizeFormat(format string) (string, bool) {
	switch strings.ToLower(format) {
	case "cdx17", "cyclonedx17", "1.7", "cdx":
		return "1.7", false
	case "cdx16", "cyclonedx16", "1.6":
		return "1.6", false
	case "cdx15", "cyclonedx15", "1.5":
		return "1.5", false
	case "cdx14", "cyclonedx14", "1.4":
		return "1.4", false
	case "cdx13", "cyclonedx13", "1.3":
		return "1.3", false
	case "cdx12", "cyclonedx12", "1.2":
		return "1.2", false
	case "json", "raw":
		return "", true
	default:
		return "1.7", false
	}
}
