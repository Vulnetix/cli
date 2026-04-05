package cdx

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vulnetix/cli/internal/gitctx"
	"github.com/vulnetix/cli/internal/scan"
)

// CycloneDX BOM structs for 1.6 and 1.7 output.

// BOM is the top-level CycloneDX Bill of Materials.
type BOM struct {
	BOMFormat       string          `json:"bomFormat"`
	SpecVersion     string          `json:"specVersion"`
	SerialNumber    string          `json:"serialNumber"`
	Version         int             `json:"version"`
	Metadata        *Metadata       `json:"metadata,omitempty"`
	Components      []Component     `json:"components,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

// Metadata describes the BOM creation context (CycloneDX 1.5+).
type Metadata struct {
	Timestamp  string                  `json:"timestamp"`
	Lifecycles []Lifecycle             `json:"lifecycles,omitempty"`
	Tools      *Tools                  `json:"tools,omitempty"`
	Authors    []OrganizationalContact `json:"authors,omitempty"`
	// Component is the top-level subject described by this BOM.
	Component  *Component              `json:"component,omitempty"`
	Properties []Property              `json:"properties,omitempty"`
}

// Lifecycle describes a phase in the product lifecycle (CycloneDX 1.5+).
// Use the Phase field for standard phases; set Name + Description for custom phases.
type Lifecycle struct {
	Phase       string `json:"phase,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// OrganizationalContact describes a person or organisation.
type OrganizationalContact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
}

// Tools holds tool information in CycloneDX format.
type Tools struct {
	Components []Component `json:"components,omitempty"`
}

// Component represents a software component.
type Component struct {
	Type               string                  `json:"type"`
	BOMRef             string                  `json:"bom-ref,omitempty"`
	Name               string                  `json:"name"`
	Version            string                  `json:"version,omitempty"`
	Description        string                  `json:"description,omitempty"`
	Scope              string                  `json:"scope,omitempty"`
	Purl               string                  `json:"purl,omitempty"`
	// Authors is supported in CycloneDX 1.6+.
	Authors            []OrganizationalContact `json:"authors,omitempty"`
	ExternalReferences []ExternalReference     `json:"externalReferences,omitempty"`
	Properties         []Property              `json:"properties,omitempty"`
}

// ExternalReference is an external URL resource associated with a component or the BOM.
type ExternalReference struct {
	// Type is one of the CycloneDX defined types: vcs, website, issue-tracker,
	// distribution, license, build-meta, build-system, release-notes, other, etc.
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Property is a name-value pair.
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ScanContext carries optional environment-enrichment data passed to BOM builders.
// All fields are optional; nil pointers are silently ignored.
type ScanContext struct {
	// Git is the git repository context collected from the scanned directory.
	Git *gitctx.GitContext
	// System is the host/process environment at scan time.
	System *gitctx.SystemInfo
	// ToolVersion is the version string injected at build time (e.g. "1.2.3").
	ToolVersion string
}

// Vulnerability represents a CycloneDX vulnerability entry.
type Vulnerability struct {
	BOMRef      string      `json:"bom-ref,omitempty"`
	ID          string      `json:"id"`
	Source      *Source     `json:"source,omitempty"`
	Ratings     []Rating    `json:"ratings,omitempty"`
	Description string      `json:"description,omitempty"`
	Affects     []Affect    `json:"affects,omitempty"`
	Analysis    *Analysis   `json:"analysis,omitempty"`
	Properties  []Property  `json:"properties,omitempty"`
	Advisories  []Advisory  `json:"advisories,omitempty"`
}

// Source identifies where vulnerability data comes from.
type Source struct {
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Rating is a vulnerability scoring entry.
type Rating struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity,omitempty"`
	Method   string  `json:"method,omitempty"`
	Source   *Source `json:"source,omitempty"`
}

// Affect identifies a component affected by a vulnerability.
type Affect struct {
	Ref string `json:"ref"`
}

// Analysis contains vulnerability analysis state.
type Analysis struct {
	State string `json:"state,omitempty"`
}

// Advisory is an external advisory reference.
type Advisory struct {
	URL string `json:"url,omitempty"`
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

// vulnSourceForScores determines the vulnerability source name for CycloneDX output
// when scores are available (VulnSummary path from BuildFromScanTasks).
// When the scores contain a "vulnetix" source, the name is "Vulnetix VDB".
// Otherwise, the first non-empty score source is used as the attribution name.
// The URL is always https://www.vulnetix.com/vdb.
func vulnSourceForScores(scores []scan.ScoreEntry) *Source {
	for _, s := range scores {
		if s.Source == "vulnetix" {
			return &Source{Name: "Vulnetix VDB", URL: "https://www.vulnetix.com/vdb"}
		}
	}
	for _, s := range scores {
		if s.Source != "" {
			return &Source{Name: s.Source, URL: "https://www.vulnetix.com/vdb"}
		}
	}
	// Default: no score sources known, attribute to Vulnetix VDB.
	return &Source{Name: "Vulnetix VDB", URL: "https://www.vulnetix.com/vdb"}
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

// BuildFromScanTasks creates a CycloneDX BOM from completed scan tasks.
func BuildFromScanTasks(tasks []*scan.ScanTask, specVersion string, scanCtx *ScanContext) *BOM {
	if specVersion == "" {
		specVersion = "1.7"
	}

	toolVersion := "cli"
	if scanCtx != nil && scanCtx.ToolVersion != "" {
		toolVersion = scanCtx.ToolVersion
	}

	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  specVersion,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Lifecycles: []Lifecycle{{Phase: "build"}},
			Tools: &Tools{
				Components: []Component{
					{Type: "application", Name: "vulnetix-sca", Version: toolVersion},
				},
			},
		},
	}

	if scanCtx != nil {
		populateMetadataFromContext(bom.Metadata, scanCtx)
	}

	// Track components by package name+version to deduplicate
	componentRefs := map[string]string{} // "name@version" -> bom-ref

	allVulns := scan.AllVulns(tasks)

	for _, v := range allVulns {
		// Ensure the affected component exists
		compKey := v.PackageName + "@" + v.PackageVer
		bomRef, exists := componentRefs[compKey]
		if !exists && v.PackageName != "" {
			bomRef = fmt.Sprintf("pkg:%s@%s", v.PackageName, v.PackageVer)
			componentRefs[compKey] = bomRef
			bom.Components = append(bom.Components, Component{
				Type:    "library",
				BOMRef:  bomRef,
				Name:    v.PackageName,
				Version: v.PackageVer,
			})
		}

		// Build vulnerability entry
		vuln := Vulnerability{
			BOMRef: v.VulnID,
			ID:     v.VulnID,
			Source: vulnSourceForScores(v.Scores),
		}

		// Add ratings from scores
		for _, s := range v.Scores {
			method := scoreTypeToMethod[s.Type]
			if method == "" {
				method = "other"
			}
			r := Rating{
				Score:    s.Score,
				Severity: v.Severity,
				Method:   method,
			}
			if s.Source != "" {
				r.Source = &Source{Name: s.Source}
			}
			if s.Type == "epss" || s.Type == "coalition_ess" {
				r.Source = &Source{Name: s.Type}
			}
			vuln.Ratings = append(vuln.Ratings, r)
		}

		// Add affects reference
		if bomRef != "" {
			vuln.Affects = append(vuln.Affects, Affect{Ref: bomRef})
		}

		// Handle malicious packages
		if v.IsMalicious {
			vuln.Analysis = &Analysis{State: "exploitable"}
			vuln.Properties = append(vuln.Properties, Property{
				Name:  "vulnetix:malware",
				Value: "true",
			})
		}

		// Add source file property
		if v.SourceFile != "" {
			vuln.Properties = append(vuln.Properties, Property{
				Name:  "vulnetix:source-file",
				Value: v.SourceFile,
			})
		}

		bom.Vulnerabilities = append(bom.Vulnerabilities, vuln)
	}

	return bom
}

// WriteJSON writes the BOM as indented JSON to the writer.
func (b *BOM) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(b)
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
		projName := gitProjectName(g)
		projVersion := gitProjectVersion(g)

		comp := &Component{
			Type:        "application",
			BOMRef:      "urn:project",
			Name:        projName,
			Version:     projVersion,
			Description: "Source code repository",
		}

		// VCS external references (one per remote URL).
		for _, u := range g.RemoteURLs {
			comp.ExternalReferences = append(comp.ExternalReferences, ExternalReference{
				Type: "vcs",
				URL:  u,
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

// gitProjectName derives a human-readable project name from the git context.
// Priority: first remote URL path → repo root directory name → "unknown".
func gitProjectName(g *gitctx.GitContext) string {
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

// gitProjectVersion returns the best available version string for the project.
// Priority: first tag at HEAD → short commit SHA → empty.
func gitProjectVersion(g *gitctx.GitContext) string {
	if len(g.HeadTags) > 0 {
		return g.HeadTags[0]
	}
	if len(g.CurrentCommit) >= 8 {
		return g.CurrentCommit[:8]
	}
	return g.CurrentCommit
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
	return []string{"1.6", "1.7"}
}

// NormalizeFormat maps user-facing format names to spec versions or output type.
// Returns (specVersion, isRawJSON).
func NormalizeFormat(format string) (string, bool) {
	switch strings.ToLower(format) {
	case "cdx17", "cyclonedx17", "1.7", "cdx":
		return "1.7", false
	case "cdx16", "cyclonedx16", "1.6":
		return "1.6", false
	case "json", "raw":
		return "", true
	default:
		return "1.7", false
	}
}
