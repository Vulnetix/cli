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
	"encoding/json"
	"fmt"
	"runtime"

	"github.com/vulnetix/cli/v3/internal/gitctx"
)

// ─── Envelope types (mirror vdb-api/internal/handler/v2_cli_common.go) ────

// CliEnv carries local-machine context. Every field is optional; older CLIs
// keep working as new fields are added server-side.
type CliEnv struct {
	CliVersion      string          `json:"cliVersion,omitempty"`
	Commit          string          `json:"commit,omitempty"`
	BuildDate       string          `json:"buildDate,omitempty"`
	Platform        string          `json:"platform,omitempty"`
	Arch            string          `json:"arch,omitempty"`
	OS              string          `json:"os,omitempty"`
	Hostname        string          `json:"hostname,omitempty"`
	Shell           string          `json:"shell,omitempty"`
	Git             *CliGitContext  `json:"git,omitempty"`
	PackageManagers []CliPackageMgr `json:"packageManagers,omitempty"`
	MemoryPath      string          `json:"memoryPath,omitempty"`
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
}

type CliSCARequest struct {
	Purls   []string      `json:"purls"`
	Options CliSCAOptions `json:"options,omitempty"`
}

type CliSCAResponse struct {
	CycloneDX    map[string]any        `json:"cyclonedx"`
	Reachability []CliReachabilityHit  `json:"reachability"`
	Stats        CliSCAStats           `json:"stats"`
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

// CliScan — POST /v2/cli.scan. Superset of CliSCA with container/IaC inputs.
func (c *Client) CliScan(env CliEnv, req CliScanRequest) (*CliResponse[CliSCAResponse], error) {
	return cliPostWithEnv[CliSCAResponse](c, "cli.scan", env, req)
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

// Stub-class endpoints (sast/secrets/iac/containers/license/ai/trends) — same
// shape as other ids-style POSTs; backend returns shape-stable empty payloads
// until the per-subcommand wire-up lands.
func (c *Client) CliSAST(env CliEnv, payload any) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.sast", env, payload)
}
func (c *Client) CliSecrets(env CliEnv, payload any) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.secrets", env, payload)
}
func (c *Client) CliIAC(env CliEnv, payload any) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.iac", env, payload)
}
func (c *Client) CliContainers(env CliEnv, payload any) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.containers", env, payload)
}
func (c *Client) CliLicense(env CliEnv, purls []string) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.license", env, CliPurlsRequest{Purls: purls})
}
func (c *Client) CliAI(env CliEnv, payload any) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.ai", env, payload)
}
func (c *Client) CliTrends(env CliEnv, payload any) (*CliResponse[map[string]any], error) {
	return cliPostWithEnv[map[string]any](c, "cli.trends", env, payload)
}

// Suppress unused import errors if generic helper inlining hides usage.
var _ = cliPost[any]
