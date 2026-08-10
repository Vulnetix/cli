package protocol

// The vulnetix/* extension methods.
//
// Every params and result type here is an object, never an array or a bare
// value. That is what lets a field be added without bumping ProtocolVersion:
// an older client ignores what it does not know, and a newer client reading a
// field an older server never sent gets a zero value it can handle. An array
// result would make any addition a breaking change.

// ── vulnetix/serverInfo ──────────────────────────────────────────────────────

// ServerInfoResult is the handshake. The client checks ProtocolVersion for an
// exact match and CLIVersion against its declared range, then uses Capabilities
// to hide UI for anything this build cannot do, rather than offering it and
// failing at call time.
type ServerInfoResult struct {
	ProtocolVersion int    `json:"protocolVersion"`
	CLIVersion      string `json:"cliVersion"`
	Commit          string `json:"commit,omitempty"`
	BuildDate       string `json:"buildDate,omitempty"`
	GoVersion       string `json:"goVersion,omitempty"`
	Platform        string `json:"platform,omitempty"`

	// Capabilities names the analysis families this build supports.
	Capabilities []string `json:"capabilities"`

	// RulesEmbedded and RuleKinds describe the compiled-in corpus, which is
	// what the client shows as "evaluated N rules" instead of an opaque wait.
	RulesEmbedded int            `json:"rulesEmbedded"`
	RuleKinds     map[string]int `json:"ruleKinds,omitempty"`
}

// ── vulnetix/scanWorkspace ───────────────────────────────────────────────────

// ScanFeatures toggles analysis families for one run. A nil pointer means
// "server default", which is what lets the client send only what the user
// actually changed rather than a full set it has to keep in sync.
type ScanFeatures struct {
	SCA        *bool `json:"sca,omitempty"`
	SAST       *bool `json:"sast,omitempty"`
	Secrets    *bool `json:"secrets,omitempty"`
	IAC        *bool `json:"iac,omitempty"`
	Containers *bool `json:"containers,omitempty"`
	License    *bool `json:"license,omitempty"`
	Malscan    *bool `json:"malscan,omitempty"`
}

type ScanWorkspaceParams struct {
	// Folders to scan. Empty means every folder the client has registered.
	Folders  []string      `json:"folders,omitempty"`
	Features *ScanFeatures `json:"features,omitempty"`
	// Refresh bypasses the vulnerability-data disk cache.
	Refresh bool `json:"refresh,omitempty"`
	// GitHistory walks git history for secrets. Defaults to false in the
	// server even though the CLI defaults it true, because it walks hundreds
	// of commits and thousands of file versions: a CI job, not an editor one.
	GitHistory bool `json:"gitHistory,omitempty"`
}

type ScanCounts struct {
	BySeverity map[string]int `json:"bySeverity,omitempty"`
	ByTool     map[string]int `json:"byTool,omitempty"`
	Total      int            `json:"total"`
}

type ScanArtifacts struct {
	SBOM   string `json:"sbom,omitempty"`
	SARIF  string `json:"sarif,omitempty"`
	Memory string `json:"memory,omitempty"`
}

type GateResult struct {
	Breached bool     `json:"breached"`
	Reasons  []string `json:"reasons,omitempty"`
}

type ScanWorkspaceResult struct {
	ProtocolVersion int           `json:"protocolVersion"`
	ScanID          string        `json:"scanId"`
	DurationMS      int64         `json:"durationMs"`
	Counts          ScanCounts    `json:"counts"`
	Artifacts       ScanArtifacts `json:"artifacts,omitempty"`
	Gate            *GateResult   `json:"gate,omitempty"`

	// Degradations names what did not run to completion. Always populated when
	// something was skipped, because "no findings" and "did not look" must
	// never be indistinguishable to the person reading the result.
	Degradations []string `json:"degradations,omitempty"`
}

// ── vulnetix/scanStatus (server to client notification) ──────────────────────

// ScanStatusParams complements $/progress with data a tree view can bind to.
// $/progress renders a bar; this says which phase, how far, and whether it can
// still be cancelled, which is what a sidebar needs to show useful state.
type ScanStatusParams struct {
	ScanID      string `json:"scanId"`
	Phase       string `json:"phase"`
	Stage       string `json:"stage,omitempty"`
	Percent     *int   `json:"percent,omitempty"`
	Cancellable bool   `json:"cancellable"`
}

// ── vulnetix/findings ────────────────────────────────────────────────────────

type FindingsFilter struct {
	Tools      []string `json:"tools,omitempty"`
	Severities []string `json:"severities,omitempty"`
	Statuses   []string `json:"statuses,omitempty"`
	Path       string   `json:"path,omitempty"`
	Query      string   `json:"query,omitempty"`
}

// FindingsParams is paginated. A large repository produces thousands of
// findings and serialising them all into one message stalls the client for
// seconds before it can draw anything.
type FindingsParams struct {
	Folder  string          `json:"folder,omitempty"`
	Filter  *FindingsFilter `json:"filter,omitempty"`
	GroupBy string          `json:"groupBy,omitempty"`
	Cursor  string          `json:"cursor,omitempty"`
	Limit   int             `json:"limit,omitempty"`
}

// AnchorConfidence describes how precisely a finding was placed. Rendered as a
// subtle indicator so an approximate position is not presented as an exact one.
type AnchorConfidence string

const (
	AnchorExact   AnchorConfidence = "exact"
	AnchorSnippet AnchorConfidence = "snippet"
	AnchorLine    AnchorConfidence = "line"
	AnchorFile    AnchorConfidence = "file"
)

type FindingLocation struct {
	URI              string           `json:"uri"`
	Range            Range            `json:"range"`
	AnchorConfidence AnchorConfidence `json:"anchorConfidence,omitempty"`
}

type RelatedLocation struct {
	URI     string `json:"uri"`
	Range   Range  `json:"range"`
	Message string `json:"message,omitempty"`
}

// PackageInfo describes the dependency a finding is about, when it is about one.
type PackageInfo struct {
	Purl        string `json:"purl"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Ecosystem   string `json:"ecosystem"`
	Direct      bool   `json:"direct"`
	Scope       string `json:"scope,omitempty"`
	IsEOL       bool   `json:"isEol,omitempty"`
	IsMalicious bool   `json:"isMalicious,omitempty"`
	// PathCount is how many dependency paths introduce this package. More than
	// one is the usual reason a transitive cannot simply be upgraded.
	PathCount int `json:"pathCount,omitempty"`
}

// VulnInfo carries the exploit picture alongside the score, because a critical
// CVSS on something nobody exploits is different work from a high with a
// working exploit, and a client that only sees severity cannot tell them apart.
type VulnInfo struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`

	CVSS *float64 `json:"cvss,omitempty"`
	EPSS *float64 `json:"epss,omitempty"`
	SSVC string   `json:"ssvc,omitempty"`
	CWSS *float64 `json:"cwss,omitempty"`

	InCisaKev bool `json:"inCisaKev,omitempty"`
	InEuKev   bool `json:"inEuKev,omitempty"`
	// ExploitMaturity is none, poc, functional or weaponized.
	ExploitMaturity string `json:"exploitMaturity,omitempty"`

	CWEs []int `json:"cwes,omitempty"`
	// Reachability is reachable, not_reachable, not_assessable or unassessed.
	// The distinction between not_reachable and unassessed matters: one is an
	// answer and the other is the absence of one.
	Reachability string `json:"reachability,omitempty"`
}

type VexInfo struct {
	Status          string `json:"status,omitempty"`
	Justification   string `json:"justification,omitempty"`
	ActionStatement string `json:"actionStatement,omitempty"`
}

type SuppressionInfo struct {
	// Kind is nosec, cli or console: an inline comment, a recorded local
	// suppression, or one synced from the organisation.
	Kind      string `json:"kind,omitempty"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// Finding is the one shape every view binds to, unioning the SARIF and SCA
// worlds so a tree, a panel and a diagnostic all read the same object.
type Finding struct {
	// ID is the fingerprint for a code finding, or tool:vuln:purl for a
	// dependency one. Stable across scans, which is what lets a client keep
	// selection and expansion state through a rescan.
	ID   string `json:"id"`
	Tool string `json:"tool"`

	RuleID   string `json:"ruleId,omitempty"`
	RuleName string `json:"ruleName,omitempty"`
	Title    string `json:"title,omitempty"`
	Message  string `json:"message"`

	Severity string `json:"severity"`
	Level    string `json:"level,omitempty"`

	Location         FindingLocation   `json:"location"`
	RelatedLocations []RelatedLocation `json:"relatedLocations,omitempty"`

	Package *PackageInfo `json:"package,omitempty"`
	Vuln    *VulnInfo    `json:"vuln,omitempty"`

	Status      string           `json:"status,omitempty"`
	Vex         *VexInfo         `json:"vex,omitempty"`
	Suppression *SuppressionInfo `json:"suppression,omitempty"`

	HelpURI      string `json:"helpUri,omitempty"`
	FixAvailable bool   `json:"fixAvailable,omitempty"`
	Snippet      string `json:"snippet,omitempty"`
}

type FindingsResult struct {
	ProtocolVersion int       `json:"protocolVersion"`
	Items           []Finding `json:"items"`
	Total           int       `json:"total"`
	// NextCursor is empty on the last page.
	NextCursor string `json:"nextCursor,omitempty"`
}
