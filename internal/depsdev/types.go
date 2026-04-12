package depsdev

// VersionKey identifies a specific package version in deps.dev.
type VersionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// AdvisoryKey is a reference to an advisory associated with a package version.
type AdvisoryKey struct {
	ID string `json:"id"`
}

// Link is a URL associated with a package version (repo, homepage, docs, etc.).
type Link struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

// SLSAProvenance captures SLSA build provenance for a package version.
type SLSAProvenance struct {
	SourceRepository string `json:"sourceRepository"`
	BuildSystem      string `json:"buildSystem"`
	Verified         bool   `json:"verified"`
}

// RelatedProject references a project associated with a package version.
type RelatedProject struct {
	ProjectKey    ProjectKey `json:"projectKey"`
	RelationType  string     `json:"relationType"`
	RelationProvenance string `json:"relationProvenance"`
}

// ProjectKey identifies a project (typically a source repository).
type ProjectKey struct {
	ID string `json:"id"`
}

// VersionResponse is the full response from GET /v3/systems/{sys}/packages/{name}/versions/{ver}.
type VersionResponse struct {
	VersionKey      VersionKey       `json:"versionKey"`
	Licenses        []string         `json:"licenses"`
	AdvisoryKeys    []AdvisoryKey    `json:"advisoryKeys"`
	Links           []Link           `json:"links"`
	PublishedAt     string           `json:"publishedAt"`
	IsDefault       bool             `json:"isDefault"`
	SLSAProvenances []SLSAProvenance `json:"slsaProvenances"`
	RelatedProjects []RelatedProject `json:"relatedProjects"`
	Registries      []string         `json:"registries"`
}

// PackageKey identifies a package in deps.dev.
type PackageKey struct {
	System string `json:"system"`
	Name   string `json:"name"`
}

// VersionSummary is a brief version entry returned by GetPackage.
type VersionSummary struct {
	VersionKey  VersionKey `json:"versionKey"`
	PublishedAt string     `json:"publishedAt"`
	IsDefault   bool       `json:"isDefault"`
}

// PackageResponse is the response from GET /v3/systems/{sys}/packages/{name}.
type PackageResponse struct {
	PackageKey PackageKey       `json:"packageKey"`
	Versions   []VersionSummary `json:"versions"`
}

// ScorecardCheck is a single check in an OpenSSF Scorecard.
type ScorecardCheck struct {
	Name    string `json:"name"`
	Score   int    `json:"score"`
	Reason  string `json:"reason"`
	Details []string `json:"details"`
}

// Scorecard holds OpenSSF Scorecard data for a project.
type Scorecard struct {
	OverallScore float64          `json:"overallScore"`
	Date         string           `json:"date"`
	Checks       []ScorecardCheck `json:"checks"`
}

// ProjectResponse is the response from GET /v3/projects/{key}.
type ProjectResponse struct {
	ProjectKey    ProjectKey `json:"projectKey"`
	Scorecard     *Scorecard `json:"scorecard"`
	License       string     `json:"license"`
	OpenSSFFuzzed bool       `json:"openssfFuzzed"`
}

// AdvisoryResponse is the response from GET /v3/advisories/{key}.
type AdvisoryResponse struct {
	AdvisoryKey AdvisoryKey `json:"advisoryKey"`
	URL         string      `json:"url"`
	Title       string      `json:"title"`
	Aliases     []string    `json:"aliases"`
	CVSS3Score  float64     `json:"cvss3Score"`
	CVSS3Vector string      `json:"cvss3Vector"`
	Severity    string      `json:"severity"`
}

// PackageRef identifies a package to enrich via deps.dev.
type PackageRef struct {
	Name      string
	Version   string
	Ecosystem string
}

// PackageEnrichment holds all deps.dev data collected for one package@version.
type PackageEnrichment struct {
	PackageRef
	VersionData    *VersionResponse
	LatestVersion  string
	IsOutdated     bool
	VersionsBehind int
	Advisories     []AdvisoryResponse
	Project        *ProjectResponse
	Error          error
}
