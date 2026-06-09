package vdb

// CLI-only client surface. Each method targets one POST /v2/cli.<name> endpoint
// on vdb-api. The full envelope contract lives in the vdb-api side
// (internal/handler/v2_cli_common.go) — this file is the typed mirror.
//
// Endpoints are undocumented in the public OAS by design: they exist solely to
// serve the Vulnetix CLI (and embedded clients like the GitHub Action) with
// purpose-built payloads — far fewer round-trips than the granular userspace
// /v2/vuln/{id}/* surface.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"time"

	"github.com/vulnetix/cli/v3/internal/gitctx"
)

// ─── Envelope types (mirror vdb-api/internal/handler/v2_cli_common.go) ────

// CliEnv carries local-machine context. Every field is optional; older CLIs
// keep working as new fields are added server-side.
type CliEnv struct {
	CliVersion      string                `json:"cliVersion,omitempty"`
	Commit          string                `json:"commit,omitempty"`
	BuildDate       string                `json:"buildDate,omitempty"`
	Platform        string                `json:"platform,omitempty"`
	Arch            string                `json:"arch,omitempty"`
	OS              string                `json:"os,omitempty"`
	Hostname        string                `json:"hostname,omitempty"`
	Shell           string                `json:"shell,omitempty"`
	Git             *CliGitContext        `json:"git,omitempty"`
	PackageManagers []CliPackageMgr       `json:"packageManagers,omitempty"`
	MemoryPath      string                `json:"memoryPath,omitempty"`
	Licenses        []CliLicenseHit       `json:"licenses,omitempty"`
	Manifests       []CliManifestMetadata `json:"manifests,omitempty"`
	ToolMetadata    *CliSBOMToolMetadata  `json:"toolMetadata,omitempty"`
	Capabilities    []CliPMCapability     `json:"capabilities,omitempty"`
}

// CliLicenseHit mirrors vdb-api/internal/handler/v2_cli_common.go.
type CliLicenseHit struct {
	SPDXID      string `json:"spdxId,omitempty"`
	Name        string `json:"name,omitempty"`
	URL         string `json:"url,omitempty"`
	Source      string `json:"source,omitempty"`
	Acknowledge string `json:"acknowledgement,omitempty"`
	Text        string `json:"text,omitempty"`
}

// CliManifestMetadata describes one manifest the CLI parsed. Content is the raw
// file body; it is populated only on the chunk-0 env (the chunk that carries
// Packages, where persistence runs) to keep within the request size cap.
type CliManifestMetadata struct {
	Path        string `json:"path"`
	Ecosystem   string `json:"ecosystem,omitempty"`
	IsLock      bool   `json:"isLock,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Size        int    `json:"size,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	License     string `json:"license,omitempty"` // declared license from the manifest field
	Provider    string `json:"provider,omitempty"`
	Registry    string `json:"registry,omitempty"`
	Content     string `json:"content,omitempty"` // raw manifest body (chunk-0 only)
}

// CliSBOMToolMetadata describes the CLI tool itself for the SBOMToolMetadata row.
type CliSBOMToolMetadata struct {
	ToolName    string `json:"toolName,omitempty"`
	ToolVersion string `json:"toolVersion,omitempty"`
	ToolVendor  string `json:"toolVendor,omitempty"`
	ToolHash    string `json:"toolHash,omitempty"`
}

// CliPMCapability — one detected package-manager capability on the host. The
// binary/version fields describe a concrete resolver binary; Authoritative is
// true when a lockfile narrowed the manifest to this specific binary.
type CliPMCapability struct {
	Ecosystem      string  `json:"ecosystem"`
	CapabilityName string  `json:"capabilityName"`
	Supported      bool    `json:"supported"`
	Detected       bool    `json:"detected"`
	Confidence     float64 `json:"confidence,omitempty"`
	Evidence       string  `json:"evidence,omitempty"`
	FilePath       string  `json:"filePath,omitempty"`
	Binary         string  `json:"binary,omitempty"`
	BinaryPath     string  `json:"binaryPath,omitempty"`
	Version        string  `json:"version,omitempty"`
	VersionCommand string  `json:"versionCommand,omitempty"`
	Authoritative  bool    `json:"authoritative,omitempty"`
}

// CliGitContext is the subset of repo state useful for triage correlation.
type CliGitContext struct {
	Branch   string   `json:"branch,omitempty"`
	Commit   string   `json:"commit,omitempty"`
	Author   string   `json:"author,omitempty"`
	Remotes  []string `json:"remotes,omitempty"`
	Dirty    bool     `json:"dirty,omitempty"`
	RepoRoot string   `json:"repoRoot,omitempty"`
}

// CliPackageMgr is one manifest detected near the cwd.
type CliPackageMgr struct {
	Ecosystem string `json:"ecosystem"`
	Manifest  string `json:"manifest,omitempty"`
	IsLock    bool   `json:"isLock,omitempty"`
}

// cliRequestEnvelope wraps every CLI request. Payload is opaque on the wire;
// per-method helpers populate it with a typed struct.
type cliRequestEnvelope struct {
	Env     CliEnv `json:"env"`
	Payload any    `json:"payload,omitempty"`
}

// CliResponseMeta is the top-level meta block on every response.
type CliResponseMeta struct {
	Tier            string          `json:"tier"`
	EndpointVersion string          `json:"endpointVersion"`
	RequestID       string          `json:"requestId"`
	Timestamp       int64           `json:"timestamp"`
	TierGated       map[string]bool `json:"tierGated,omitempty"`
}

// cliResponseEnvelope is the wire-level decode shape. Data is left as raw JSON
// so per-method helpers can decode into their own response type.
type cliResponseEnvelope struct {
	Meta CliResponseMeta `json:"meta"`
	Data json.RawMessage `json:"data"`
}

// CliResponse couples meta + the typed payload after decode. Returned by every
// method so callers can surface tier-gated affordances in the CLI output.
type CliResponse[T any] struct {
	Meta CliResponseMeta
	Data T
}

// ─── Per-endpoint request / response types ────────────────────────────────

type CliSCAOptions struct {
	IncludeReachability *bool `json:"includeReachability,omitempty"`
	IncludeVEX          *bool `json:"includeVEX,omitempty"`
	// Gate-data toggles: request per-package policy signals (PackageInsights)
	// only when a `scan` gate is active, so a plain scan pays nothing extra.
	IncludeCooldown     bool `json:"includeCooldown,omitempty"`     // installed-version publish dates (--cooldown)
	IncludeVersionLag   bool `json:"includeVersionLag,omitempty"`   // full version list (--version-lag)
	IncludeSafeVersions bool `json:"includeSafeVersions,omitempty"` // ranked Safe-Harbour versions (--sca-autofix)
	IncludeEOL          bool `json:"includeEol,omitempty"`          // package-level EOL (--block-eol)
	IncludeMalware      bool `json:"includeMalware,omitempty"`      // malicious-package check (--block-malware)
}

type CliSCARequest struct {
	Purls    []string          `json:"purls"`
	Packages []CliPackageEntry `json:"packages,omitempty"`
	Options  CliSCAOptions     `json:"options,omitempty"`
	// IngestionSnapshotUuid is set on discovery chunks (i>0) to the snapshot UUID
	// chunk 0 returned, so the server appends each chunk's findings under one run
	// instead of persisting only chunk 0's. Empty on chunk 0.
	IngestionSnapshotUuid string `json:"ingestionSnapshotUuid,omitempty"`
}

// CliPackageChecksum represents an integrity hash for a package.
type CliPackageChecksum struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

// CliPackageEntry — per-package dependency-path context so the server can
// compute FindingIntroducedVia paths.
type CliPackageEntry struct {
	Purl          string               `json:"purl"`
	Name          string               `json:"name,omitempty"`
	Version       string               `json:"version,omitempty"`
	Ecosystem     string               `json:"ecosystem,omitempty"`
	ManifestFile  string               `json:"manifestFile,omitempty"`
	Scope         string               `json:"scope,omitempty"`
	License       string               `json:"license,omitempty"`
	IntroducedVia [][]string           `json:"introducedVia,omitempty"`
	Checksums     []CliPackageChecksum `json:"checksums,omitempty"`
}

type CliSCAResponse struct {
	CycloneDX         map[string]any        `json:"cyclonedx"`
	Reachability      []CliReachabilityHit  `json:"reachability"`
	Stats             CliSCAStats           `json:"stats"`
	IngestionSnapshot *CliIngestionSnapshot `json:"ingestionSnapshot,omitempty"`
	Findings          []CliFindingResult    `json:"findings,omitempty"`
	PackageInsights   []CliPackageInsight   `json:"packageInsights,omitempty"`
}

// CliPackageInsight carries per-package policy-gate signals the server computes
// for --cooldown, --version-lag, --block-eol and --block-malware. Mirrors the
// vdb-api handler.CliPackageInsight contract.
type CliPackageInsight struct {
	Purl           string                  `json:"purl"`
	Name           string                  `json:"name"`
	Version        string                  `json:"version"`
	Ecosystem      string                  `json:"ecosystem"`
	PublishedAt    *int64                  `json:"publishedAt,omitempty"`    // ms epoch — installed version (--cooldown)
	PublishSource  string                  `json:"publishSource,omitempty"`  // "db" | "deps.dev"
	LatestVersions []CliVersionStamp       `json:"latestVersions,omitempty"` // newest-first by publish date (--version-lag)
	SafeVersions   []CliSafeHarbourVersion `json:"safeVersions,omitempty"`
	SafeHarbour    *CliSafeHarbourSummary  `json:"safeHarbour,omitempty"`
	IsEOL          bool                    `json:"isEol,omitempty"`
	EOLFrom        string                  `json:"eolFrom,omitempty"`
	IsMalicious    bool                    `json:"isMalicious,omitempty"`
	MalwareSource  string                  `json:"malwareSource,omitempty"`
}

// CliVersionStamp is one version + its publish date (ms epoch).
type CliVersionStamp struct {
	Version     string `json:"version"`
	PublishedAt *int64 `json:"publishedAt,omitempty"`
}

// CliSafeHarbourVersion mirrors the vdb-api SafeHarbourVersion shape used by
// /v2/cli.sca. The CLI only depends on the stable subset below; extra
// server-side fields are ignored by encoding/json.
type CliSafeHarbourVersion struct {
	Version            string   `json:"version,omitempty"`
	VulnerabilityCount int      `json:"vulnerabilityCount,omitempty"`
	SafeHarbourScore   float64  `json:"safeHarbourScore,omitempty"`
	IsMalware          bool     `json:"isMalware,omitempty"`
	ExploitCount       int      `json:"exploitCount,omitempty"`
	CveIds             []string `json:"cveIds,omitempty"`
}

// CliSafeHarbourSummary mirrors the recommendation block returned with ranked
// safe versions. Recommendation.Version is used as a fallback by --sca-autofix.
type CliSafeHarbourSummary struct {
	RecommendedVersions []string                      `json:"recommendedVersions,omitempty"`
	HighestScore        float64                       `json:"highestScore,omitempty"`
	Recommendation      *CliSafeHarbourRecommendation `json:"recommendation,omitempty"`
}

type CliSafeHarbourRecommendation struct {
	Version string `json:"version,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// CliIngestionSnapshot is the persistent snapshot the server creates when
// the authenticated org has a SaaS-side Org row. URL is the user-facing link.
type CliIngestionSnapshot struct {
	Uuid      string `json:"uuid"`
	URL       string `json:"url"`
	CreatedAt int64  `json:"createdAt"`
}

// CliFindingResult mirrors the persisted Finding for reachability correlation.
type CliFindingResult struct {
	FindingID      string                 `json:"findingId"`
	FindingUuid    string                 `json:"findingUuid"`
	PackageName    string                 `json:"packageName,omitempty"`
	PackageVersion string                 `json:"packageVersion,omitempty"`
	Purl           string                 `json:"purl,omitempty"`
	IntroducedVia  []CliIntroducedViaPath `json:"introducedVia,omitempty"`
}

// CliIntroducedViaPath mirrors FindingIntroducedVia rows.
type CliIntroducedViaPath struct {
	PathIndex      int      `json:"pathIndex"`
	PathLength     int      `json:"pathLength"`
	PackageManager string   `json:"packageManager"`
	ManifestFile   string   `json:"manifestFile"`
	DependencyPath string   `json:"dependencyPath"`
	DependencyKeys []string `json:"dependencyKeys"`
}

// CliSCAReachabilityRequest is the payload for the reachability post-step.
type CliSCAReachabilityRequest struct {
	IngestionSnapshotUuid string                   `json:"ingestionSnapshotUuid"`
	Results               []CliReachabilityPayload `json:"results"`
}

// CliReachabilityPayload is one local reachability hit (tree-sitter OR grep-symbol).
type CliReachabilityPayload struct {
	CveID                  string `json:"cveId"`
	FindingUuid            string `json:"findingUuid,omitempty"`
	PackageName            string `json:"packageName"`
	PackageVersion         string `json:"packageVersion,omitempty"`
	Purl                   string `json:"purl,omitempty"`
	Language               string `json:"language,omitempty"`
	Ecosystem              string `json:"ecosystem,omitempty"`
	Source                 string `json:"source"`
	Verdict                string `json:"verdict"`
	TreeSitterQueryUuid    string `json:"treeSitterQueryUuid,omitempty"`
	QueryHash              string `json:"queryHash,omitempty"`
	MatchedFile            string `json:"matchedFile,omitempty"`
	MatchedRoutine         string `json:"matchedRoutine,omitempty"`
	MatchedModule          string `json:"matchedModule,omitempty"`
	MatchStartLine         int    `json:"matchStartLine,omitempty"`
	MatchEndLine           int    `json:"matchEndLine,omitempty"`
	EvidenceJSON           string `json:"evidenceJSON,omitempty"`
	MemoryVexStatus        string `json:"memoryVexStatus,omitempty"`
	MemoryVexJustification string `json:"memoryVexJustification,omitempty"`
	MemoryVexAction        string `json:"memoryVexAction,omitempty"`
	Severity               string `json:"severity,omitempty"`
	FixedVersion           string `json:"fixedVersion,omitempty"`
}

// CliFinalizeRequest reports the scan's policy-gate decision back to the
// server, anchored to the IngestionSnapshot.uuid from /v2/cli.sca.
type CliFinalizeRequest struct {
	IngestionSnapshotUuid string           `json:"ingestionSnapshotUuid"`
	ExitCode              int              `json:"exitCode"`               // 0 = pass, 1 = break build
	BreakBuild            bool             `json:"breakBuild"`             // true when a gate breached
	Gates                 []CliGateResult  `json:"gates"`                  // per-gate breach detail (empty when clean)
	ControlFlags          []CliControlFlag `json:"controlFlags,omitempty"` // every control flag in effect (incl. non-breaching)
}

// CliGateResult is one gate's decision — mirrors cmd.GateBreach.
type CliGateResult struct {
	Gate    string `json:"gate"`
	Count   int    `json:"count"`
	Message string `json:"message"`
}

// CliControlFlag is one control flag in effect for the scan (e.g.
// {"--severity","high"}, {"--block-malware","true"}). Captures every control
// flag the user set — not only the ones that breached — so the server can
// reconstruct the full invocation for the build-outcome display.
type CliControlFlag struct {
	Flag  string `json:"flag"`
	Value string `json:"value"`
}

// CliFinalizeResponse is the success body.
type CliFinalizeResponse struct {
	Persisted bool `json:"persisted"`
}

// CliSCAReachabilityResponse is the success body.
type CliSCAReachabilityResponse struct {
	Persisted   int    `json:"persisted"`
	SBOMUrl     string `json:"sbomUrl,omitempty"`
	VEXUrl      string `json:"vexUrl,omitempty"`
	OpenVexUuid string `json:"openVexUuid,omitempty"`
}

// CliSARIFRequest is the shared payload for every SARIF-shaped subcommand
// (sast / secrets / iac / containers / license).
type CliSARIFRequest struct {
	SARIF    map[string]any    `json:"sarif"`
	Findings []CliSARIFFinding `json:"findings"`
	// IngestionSnapshotUuid is empty on chunk 0 (server creates the snapshot/run)
	// and set on chunks 1..N to the uuid chunk 0 returned, so the server appends
	// each chunk's findings under one snapshot/run instead of creating new ones.
	// Lets the CLI split a large SARIF submission into sub-8-MiB requests.
	IngestionSnapshotUuid string `json:"ingestionSnapshotUuid,omitempty"`
}

// CliSARIFFinding mirrors vdb-api/internal/handler/cli_persist_sarif.go.
type CliSARIFFinding struct {
	RuleID           string   `json:"ruleId"`
	RuleName         string   `json:"ruleName,omitempty"`
	Message          string   `json:"message,omitempty"`
	Severity         string   `json:"severity,omitempty"`
	Level            string   `json:"level,omitempty"`
	SecuritySeverity string   `json:"securitySeverity,omitempty"`
	File             string   `json:"file,omitempty"`
	PackagePurl      string   `json:"packagePurl,omitempty"`
	StartLine        int      `json:"startLine,omitempty"`
	EndLine          int      `json:"endLine,omitempty"`
	Fingerprint      string   `json:"fingerprint,omitempty"`
	CWEs             []int    `json:"cwes,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	SARIFGuid        string   `json:"sarifGuid,omitempty"`

	Description      string `json:"description,omitempty"`
	CodeSnippet      string `json:"codeSnippet,omitempty"`
	SnippetStartLine int    `json:"snippetStartLine,omitempty"`
	SnippetEndLine   int    `json:"snippetEndLine,omitempty"`

	MemoryVexStatus        string `json:"memoryVexStatus,omitempty"`
	MemoryVexJustification string `json:"memoryVexJustification,omitempty"`
	MemoryVexAction        string `json:"memoryVexAction,omitempty"`
}

// CliSARIFResponse is the typed response from every SARIF endpoint.
type CliSARIFResponse struct {
	IngestionSnapshot *CliIngestionSnapshot `json:"ingestionSnapshot,omitempty"`
	Findings          []CliFindingResult    `json:"findings,omitempty"`
	Stats             CliSARIFStats         `json:"stats"`
}

// CliSARIFStats summarises the run for end-of-scan CLI output.
type CliSARIFStats struct {
	Findings   int            `json:"findings"`
	Rules      int            `json:"rules"`
	BySeverity map[string]int `json:"bySeverity"`
}

type CliReachabilityHit struct {
	VulnID      string           `json:"vulnId"`
	Purl        string           `json:"purl,omitempty"`
	Source      string           `json:"source,omitempty"`
	Language    string           `json:"language"`
	Name        string           `json:"name"`
	QueryText   string           `json:"queryText"`
	QueryHash   string           `json:"queryHash,omitempty"`
	Description string           `json:"description,omitempty"`
	DerivedBy   string           `json:"derivedBy,omitempty"`
	Captures    []map[string]any `json:"captures,omitempty"`
	Predicates  []map[string]any `json:"predicates,omitempty"`
}

type CliSCAStats struct {
	PurlsRequested       int `json:"purlsRequested"`
	PurlsResolved        int `json:"purlsResolved"`
	VulnerabilitiesFound int `json:"vulnerabilitiesFound"`
	ReachabilityQueries  int `json:"reachabilityQueries"`
}

// CliScanRequest is the superset payload for /v2/cli.scan.
type CliScanRequest struct {
	CliSCARequest
	ContainerImages []string `json:"containerImages,omitempty"`
	IaCFrameworks   []string `json:"iacFrameworks,omitempty"`
	Languages       []string `json:"languages,omitempty"`
}

// CliIDsRequest is the standard { ids: [...] } shape.
type CliIDsRequest struct {
	IDs []string `json:"ids"`
}

// CliPurlsRequest — { purls: [...] }.
type CliPurlsRequest struct {
	Purls []string `json:"purls"`
}

// CliVulnRequest fetches a single envelope.
type CliVulnRequest struct {
	Identifier string `json:"identifier"`
}

// CliTriageRequest mirrors the /v2/triage filters in body form.
type CliTriageRequest struct {
	Severity []string `json:"severity,omitempty"`
	MinCvss  float64  `json:"minCvss,omitempty"`
	MinEpss  float64  `json:"minEpss,omitempty"`
	InKev    *bool    `json:"inKev,omitempty"`
	Since    string   `json:"since,omitempty"`
	Limit    int      `json:"limit,omitempty"`
	Offset   int      `json:"offset,omitempty"`
}

// CliReachabilityRequest restricts queries to specific languages.
type CliReachabilityRequest struct {
	IDs       []string `json:"ids"`
	Languages []string `json:"languages,omitempty"`
}

// CliCweGuidanceRequest accepts CWE-* ids.
type CliCweGuidanceRequest struct {
	CweIDs []string `json:"cweIds"`
}

// CliRemediationRequest carries per-id context (ecosystem, packageName, etc.).
type CliRemediationRequest struct {
	IDs     []string          `json:"ids"`
	Context map[string]string `json:"context,omitempty"`
}

type CliPackageFirewallConfigRequest struct {
	CvssThreshold   *float64 `json:"cvssThreshold,omitempty"`
	EpssThreshold   *float64 `json:"epssThreshold,omitempty"`
	CessThreshold   *float64 `json:"cessThreshold,omitempty"`
	BlockMalware    *bool    `json:"blockMalware,omitempty"`
	BlockEol        *bool    `json:"blockEol,omitempty"`
	BlockKev        *bool    `json:"blockKev,omitempty"`
	BlockWeaponized *bool    `json:"blockWeaponized,omitempty"`
	BlockActive     *bool    `json:"blockActive,omitempty"`
	BlockPoc        *bool    `json:"blockPoc,omitempty"`
	BlockBadActors  *bool    `json:"blockBadActors,omitempty"`
	CooldownDays    *int     `json:"cooldownDays,omitempty"`
	VersionLag      *int     `json:"versionLag,omitempty"`
}

type CliPackageFirewallMirrorRequest struct {
	Ecosystem string `json:"ecosystem"`
	URL       string `json:"url"`
	Priority  *int   `json:"priority,omitempty"`
	IsActive  *bool  `json:"isActive,omitempty"`
}

// ─── Env snapshot ────────────────────────────────────────────────────────

// SnapshotEnv assembles the CliEnv block from the running CLI process. Safe
// to call at the start of every CLI command; reads are cheap (gitctx walks
// the cwd once, ManifestFiles is a static map lookup). Callers should pass
// the version/commit/buildDate constants the cmd package already plumbs.
func SnapshotEnv(cwd, cliVersion, cliCommit, cliBuildDate string) CliEnv {
	env := CliEnv{
		CliVersion: cliVersion,
		Commit:     cliCommit,
		BuildDate:  cliBuildDate,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		Platform:   runtime.GOOS, // mirrors config.DetectPlatform shape
	}

	if sys := gitctx.CollectSystemInfo(); sys != nil {
		env.Hostname = sys.Hostname
		env.Shell = sys.Shell
	}

	if cwd != "" {
		if gc := gitctx.Collect(cwd); gc != nil {
			git := &CliGitContext{
				Branch:   gc.CurrentBranch,
				Commit:   gc.CurrentCommit,
				Author:   gc.HeadCommitAuthor,
				Remotes:  gc.RemoteURLs,
				Dirty:    gc.IsDirty,
				RepoRoot: gc.RepoRootPath,
			}
			env.Git = git
		}
	}

	env.ToolMetadata = &CliSBOMToolMetadata{
		ToolName:    "vulnetix-cli",
		ToolVersion: cliVersion,
		ToolVendor:  "Vulnetix",
		ToolHash:    cliCommit,
	}

	return env
}

// ─── Generic post helper ─────────────────────────────────────────────────

// cliPost wraps payload in the request envelope, POSTs to /cli.<route>, and
// decodes both the meta and a typed Data payload. Reuses the existing
// DoRequest pipeline (auth, retry, quota fallback). Caching is intentionally
// off — every CLI endpoint expects fresh data and the response sizes are
// small relative to the bandwidth cost of a stale answer.
func cliPost[T any](c *Client, route string, payload any) (*CliResponse[T], error) {
	body := cliRequestEnvelope{
		Env:     CliEnv{},
		Payload: payload,
	}
	// If the caller has not pre-populated env via WithEnv, fall back to a
	// minimal snapshot so analytics still have a tier hint.
	body.Env = SnapshotEnv("", "", "", "")

	raw, err := c.DoRequest("POST", "/"+route, body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", route, err)
	}
	return decodeCliResponse[T](raw)
}

// cliPostWithEnv is the explicit variant that lets the caller pass a fully-
// populated CliEnv (typical in production paths — the cmd layer already has
// the env block ready).
func cliPostWithEnv[T any](c *Client, route string, env CliEnv, payload any) (*CliResponse[T], error) {
	body := cliRequestEnvelope{Env: env, Payload: payload}
	raw, err := c.DoRequest("POST", "/"+route, body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", route, err)
	}
	return decodeCliResponse[T](raw)
}

func cliPostWithEnvContext[T any](ctx context.Context, c *Client, route string, env CliEnv, payload any) (*CliResponse[T], error) {
	if ctx == nil {
		ctx = context.Background()
	}
	bodyBytes, err := json.Marshal(cliRequestEnvelope{Env: env, Payload: payload})
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal request body: %w", route, err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+c.APIVersion+"/"+route, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create request: %w", route, err)
	}
	if err := c.addAuthHeader(req); err != nil {
		return nil, fmt.Errorf("%s: %w", route, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.NoCache || c.RefreshCache {
		req.Header.Set("Cache-Control", "no-cache")
		q := req.URL.Query()
		q.Set("_t", fmt.Sprintf("%d", time.Now().UnixMilli()))
		req.URL.RawQuery = q.Encode()
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to execute request: %w", route, err)
	}
	defer resp.Body.Close()
	c.LastRateLimit = parseRateLimitHeaders(resp)
	c.LastCacheStatus = resp.Header.Get("X-Cache")

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to read response: %w", route, err)
	}
	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		var msg string
		if err := json.Unmarshal(raw, &errResp); err == nil {
			msg = fmt.Sprintf("API error (%d): %s - %s", resp.StatusCode, errResp.Error, errResp.Details)
		} else {
			msg = fmt.Sprintf("API error (%d): %s", resp.StatusCode, string(raw))
		}
		if resp.StatusCode == http.StatusNotFound {
			return nil, &NotFoundError{Message: msg}
		}
		// Typed so the self-healing retry loop (cli_sca.go) can branch on the
		// status code and honour any Retry-After hint.
		return nil, &CliAPIError{
			StatusCode: resp.StatusCode,
			RetryAfter: resolveRetryAfter(resp.Header),
			Message:    fmt.Sprintf("%s: %s", route, msg),
		}
	}
	return decodeCliResponse[T](raw)
}

func decodeCliResponse[T any](raw []byte) (*CliResponse[T], error) {
	var wire cliResponseEnvelope
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("decode envelope: %w", err)
	}
	var data T
	if len(wire.Data) > 0 {
		if err := json.Unmarshal(wire.Data, &data); err != nil {
			return nil, fmt.Errorf("decode data: %w", err)
		}
	}
	return &CliResponse[T]{Meta: wire.Meta, Data: data}, nil
}

// ─── Typed methods (one per /v2/cli.* route) ─────────────────────────────

// CliSCA — POST /v2/cli.sca. The flagship: PURLs + env → CycloneDX 1.6 +
// reachability + stats in a single round-trip.
func (c *Client) CliSCA(env CliEnv, req CliSCARequest) (*CliResponse[CliSCAResponse], error) {
	return cliPostWithEnv[CliSCAResponse](c, "cli.sca", env, req)
}

func (c *Client) CliSCAWithContext(ctx context.Context, env CliEnv, req CliSCARequest) (*CliResponse[CliSCAResponse], error) {
	return cliPostWithEnvContext[CliSCAResponse](ctx, c, "cli.sca", env, req)
}

// CliScan — POST /v2/cli.scan. Superset of CliSCA with container/IaC inputs.
func (c *Client) CliScan(env CliEnv, req CliScanRequest) (*CliResponse[CliSCAResponse], error) {
	return cliPostWithEnv[CliSCAResponse](c, "cli.scan", env, req)
}

// CliSCAReachability — POST /v2/cli.sca-reachability. The second leg of the
// SCA round-trip: send per-CVE local reachability evidence anchored to the
// IngestionSnapshot.uuid returned from /v2/cli.sca.
func (c *Client) CliSCAReachability(env CliEnv, req CliSCAReachabilityRequest) (*CliResponse[CliSCAReachabilityResponse], error) {
	return cliPostWithEnv[CliSCAReachabilityResponse](c, "cli.sca-reachability", env, req)
}

// CliFinalize — POST /v2/cli.finalize. The final leg: report the scan's policy
// gate decision (exit code + per-gate breaches) anchored to the
// IngestionSnapshot.uuid so the server records it on the env row.
func (c *Client) CliFinalize(env CliEnv, req CliFinalizeRequest) (*CliResponse[CliFinalizeResponse], error) {
	return cliPostWithEnv[CliFinalizeResponse](c, "cli.finalize", env, req)
}

// CliVuln — POST /v2/cli.vuln. Single-vuln envelope + metrics.
func (c *Client) CliVuln(env CliEnv, identifier string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.vuln", env, CliVulnRequest{Identifier: identifier})
}

// CliTriage — POST /v2/cli.triage.
func (c *Client) CliTriage(env CliEnv, req CliTriageRequest) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.triage", env, req)
}

// CliVex — POST /v2/cli.vex. OpenVEX statements per CVE.
func (c *Client) CliVex(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.vex", env, CliIDsRequest{IDs: ids})
}

// CliKev — POST /v2/cli.kev.
func (c *Client) CliKev(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.kev", env, CliIDsRequest{IDs: ids})
}

// CliReachability — POST /v2/cli.reachability. Tier-gated on the server.
func (c *Client) CliReachability(env CliEnv, req CliReachabilityRequest) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.reachability", env, req)
}

// CliExploits — POST /v2/cli.exploits.
func (c *Client) CliExploits(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.exploits", env, CliIDsRequest{IDs: ids})
}

// CliMSRC, CliNuclei, CliSnortRules, CliYaraRules, CliAttackTechniques,
// CliIOCs, CliSightings, CliAdvisories, CliWorkarounds, CliAffected all share
// the { ids: [...] } shape on the wire.
func (c *Client) CliMSRC(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.msrc", env, CliIDsRequest{IDs: ids})
}
func (c *Client) CliNuclei(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.nuclei", env, CliIDsRequest{IDs: ids})
}
func (c *Client) CliSnortRules(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.snort-rules", env, CliIDsRequest{IDs: ids})
}
func (c *Client) CliYaraRules(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.yara-rules", env, CliIDsRequest{IDs: ids})
}
func (c *Client) CliAttackTechniques(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.attack-techniques", env, CliIDsRequest{IDs: ids})
}
func (c *Client) CliIOCs(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.iocs", env, CliIDsRequest{IDs: ids})
}
func (c *Client) CliSightings(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.sightings", env, CliIDsRequest{IDs: ids})
}
func (c *Client) CliAdvisories(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.advisories", env, CliIDsRequest{IDs: ids})
}
func (c *Client) CliWorkarounds(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.workarounds", env, CliIDsRequest{IDs: ids})
}
func (c *Client) CliAffected(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.affected", env, CliIDsRequest{IDs: ids})
}

// CliCweGuidance — POST /v2/cli.cwe-guidance.
func (c *Client) CliCweGuidance(env CliEnv, cweIDs []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.cwe-guidance", env, CliCweGuidanceRequest{CweIDs: cweIDs})
}

// CliRemediation — POST /v2/cli.remediation.
func (c *Client) CliRemediation(env CliEnv, req CliRemediationRequest) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.remediation", env, req)
}

// CliScorecard — POST /v2/cli.scorecard.
func (c *Client) CliScorecard(env CliEnv, purls []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.scorecard", env, CliPurlsRequest{Purls: purls})
}

// CliFixes — POST /v2/cli.fixes. Replaces the 3-call registry/distributions/source dance.
func (c *Client) CliFixes(env CliEnv, ids []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.fixes", env, CliIDsRequest{IDs: ids})
}

func (c *Client) CliPackageFirewallConfig(env CliEnv, req CliPackageFirewallConfigRequest) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.package-firewall-config", env, req)
}

func (c *Client) CliPackageFirewallMirror(env CliEnv, req CliPackageFirewallMirrorRequest) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.package-firewall-mirror", env, req)
}

// CliPackageFirewallGet — POST /v2/cli.package-firewall-get. Read-only: returns
// the org's policy ({"config": {...}|null}) plus every mirror across all
// ecosystems ({"mirrors": [...]}). Org is resolved from the authenticated
// request, so the payload is empty.
func (c *Client) CliPackageFirewallGet(env CliEnv) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.package-firewall-get", env, struct{}{})
}

// SARIF-shaped scan endpoints. Each returns the same persistence response
// (IngestionSnapshot + Findings + Stats) so the CLI's snapshot-URL output is
// uniform across kinds.
func (c *Client) CliSAST(env CliEnv, req CliSARIFRequest) (*CliResponse[CliSARIFResponse], error) {
	return cliPostWithEnv[CliSARIFResponse](c, "cli.sast", env, req)
}
func (c *Client) CliSecrets(env CliEnv, req CliSARIFRequest) (*CliResponse[CliSARIFResponse], error) {
	return cliPostWithEnv[CliSARIFResponse](c, "cli.secrets", env, req)
}
func (c *Client) CliIAC(env CliEnv, req CliSARIFRequest) (*CliResponse[CliSARIFResponse], error) {
	return cliPostWithEnv[CliSARIFResponse](c, "cli.iac", env, req)
}
func (c *Client) CliContainers(env CliEnv, req CliSARIFRequest) (*CliResponse[CliSARIFResponse], error) {
	return cliPostWithEnv[CliSARIFResponse](c, "cli.containers", env, req)
}
func (c *Client) CliLicense(env CliEnv, req CliSARIFRequest) (*CliResponse[CliSARIFResponse], error) {
	return cliPostWithEnv[CliSARIFResponse](c, "cli.license", env, req)
}

// Remaining stub-class endpoints (ai/trends) — these still use the legacy
// generic shape; they are not part of the SARIF persistence flow.
func (c *Client) CliAI(env CliEnv, payload any) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.ai", env, payload)
}
func (c *Client) CliTrends(env CliEnv, payload any) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.trends", env, payload)
}

// Suppress unused import errors if generic helper inlining hides usage.
var _ = cliPost[any]
