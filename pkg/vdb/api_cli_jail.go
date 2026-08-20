package vdb

import "context"

// ─────────────────────────────────────────────────────────────────────────
// api_cli_jail.go — the typed mirror of vdb-api's /v2/cli.jail contract.
//
// Every struct below must stay field-for-field and tag-for-tag identical to its
// twin in vdb-api/internal/handler/v2_cli_jail.go. api_cli_jail_mirror_test.go
// asserts that against a sibling checkout when one is present.
// ─────────────────────────────────────────────────────────────────────────

// Jail verdicts.
const (
	JailVerdictClear         = "clear"
	JailVerdictJailed        = "jailed"
	JailVerdictIndeterminate = "indeterminate"
	JailVerdictNoPolicy      = "no-policy"
)

// Jail rule states.
const (
	JailStatePass          = "pass"
	JailStateBreach        = "breach"
	JailStateWarn          = "warn"
	JailStateIndeterminate = "indeterminate"
	JailStateSkipped       = "skipped"
	JailStateExempt        = "exempt"
)

// CliJailRequest is the payload for POST /v2/cli.jail.
type CliJailRequest struct {
	// Mode selects the read shape: "" or "assess" gates, "explain" adds the
	// matched-item detail behind every verdict, "list" reports the rules in
	// effect without producing artefacts.
	Mode string `json:"mode,omitempty"`

	// Repo and Branch override the server-derived scope. Honoured for explain
	// and list only — an assess run that could name its own scope could name a
	// clean one.
	Repo   string `json:"repo,omitempty"`
	Branch string `json:"branch,omitempty"`

	RuleUuids []string `json:"ruleUuids,omitempty"`

	// KnownSnapshotUuids names scanner runs this invocation just created, so a
	// single-step scan-then-gate does not read its own upload as missing
	// coverage while the read replica catches up.
	KnownSnapshotUuids []string `json:"knownSnapshotUuids,omitempty"`

	IncludeVex   bool `json:"includeVex,omitempty"`
	IncludeSarif bool `json:"includeSarif,omitempty"`

	// StalenessDays and OnStale may only TIGHTEN the policy; the server ignores
	// and reports a looser request.
	StalenessDays int    `json:"stalenessDays,omitempty"`
	OnStale       string `json:"onStale,omitempty"`

	MaxLookbackDays int `json:"maxLookbackDays,omitempty"`
}

// CliJailResponse is the verdict.
//
// ExitCode is advisory: the CLI owns process exit, and code 2 (usage/config) is
// CLI-local and never appears here.
type CliJailResponse struct {
	Verdict     string `json:"verdict"`
	ExitCode    int    `json:"exitCode"`
	EvaluatedAt int64  `json:"evaluatedAt"`

	Policy     *CliJailPolicyRef         `json:"policy,omitempty"`
	Scope      CliJailScope              `json:"scope"`
	Freshness  CliJailFreshness          `json:"freshness"`
	Rules      []CliJailRuleVerdict      `json:"rules"`
	Exemptions []CliJailExemptionApplied `json:"exemptions,omitempty"`
	Vex        *CliJailVexPayload        `json:"vex,omitempty"`
	Sarif      *CliJailSarifPayload      `json:"sarif,omitempty"`
	Summary    CliJailSummary            `json:"summary"`

	Warnings []string `json:"warnings,omitempty"`
}

// CliJailPolicyRef names the policy row that decided this run.
type CliJailPolicyRef struct {
	Uuid                 string `json:"uuid"`
	Name                 string `json:"name"`
	Source               string `json:"source"` // repo | org
	EnforcementMode      string `json:"enforcementMode"`
	DefaultStalenessDays int    `json:"defaultStalenessDays"`
	OnStale              string `json:"onStale"`
	RuleCount            int    `json:"ruleCount"`
}

// CliJailScope is the resolved repo and branch the verdict is about.
//
// Echoed back because the CLI derives the same values independently, and a
// disagreement between the two is the most likely cause of a gate reporting an
// empty repo.
type CliJailScope struct {
	Repo         string `json:"repo"`
	Branch       string `json:"branch"`
	Commit       string `json:"commit,omitempty"`
	RepoSource   string `json:"repoSource"`
	BranchSource string `json:"branchSource"`
}

// CliJailFreshness is the coverage state the verdict rests on.
type CliJailFreshness struct {
	Categories []CliJailCategoryFreshness `json:"categories"`
	Missing    []string                   `json:"missing,omitempty"`
	Stale      []string                   `json:"stale,omitempty"`

	// CommitDrift is informational and never a breach.
	CommitDrift  bool   `json:"commitDrift"`
	DriftFrom    string `json:"driftFrom,omitempty"`
	DriftTo      string `json:"driftTo,omitempty"`
	WorstAgeDays int    `json:"worstAgeDays"`
}

type CliJailCategoryFreshness struct {
	Category   string             `json:"category"`
	LatestAt   int64              `json:"latestAt"`
	AgeDays    int                `json:"ageDays"`
	CommitSha  string             `json:"commitSha,omitempty"`
	Stale      bool               `json:"stale"`
	WindowDays int                `json:"windowDays"`
	Tools      []CliJailToolCover `json:"tools"`
}

type CliJailToolCover struct {
	ToolName     string `json:"toolName"`
	ToolVersion  string `json:"toolVersion,omitempty"`
	LatestAt     int64  `json:"latestAt"`
	AgeDays      int    `json:"ageDays"`
	SnapshotUuid string `json:"snapshotUuid"`
	Total        int    `json:"ingestedTotal"`
}

// CliJailRuleVerdict is one rule's outcome.
type CliJailRuleVerdict struct {
	RuleUuid   string `json:"ruleUuid"`
	Kind       string `json:"kind"`
	OrderIndex int    `json:"orderIndex"`
	Label      string `json:"label"`

	State string `json:"state"`

	Aggregate     string   `json:"aggregate"`
	Operator      string   `json:"operator"`
	Observed      float64  `json:"observed"`
	ThresholdLow  float64  `json:"thresholdLow"`
	ThresholdHigh *float64 `json:"thresholdHigh,omitempty"`

	OnBreach string `json:"onBreach"`
	Reason   string `json:"reason"`

	// Stale is true when the rule was graded on coverage past its window.
	// Always inspect this before believing a pass.
	Stale      bool     `json:"stale,omitempty"`
	Categories []string `json:"categories,omitempty"`

	Deadline      int64    `json:"deadline,omitempty"`
	DaysRemaining int      `json:"daysRemaining,omitempty"`
	Ratcheted     bool     `json:"ratcheted,omitempty"`
	Baseline      *float64 `json:"baseline,omitempty"`

	ExemptionUuid string `json:"exemptionUuid,omitempty"`

	Items []string `json:"items,omitempty"`
}

// CliJailExemptionApplied records an exemption that changed a verdict — the
// audit trail for why a red gate is green.
type CliJailExemptionApplied struct {
	Uuid       string `json:"uuid"`
	RuleUuid   string `json:"ruleUuid,omitempty"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approvedBy"`
	ExpiresAt  int64  `json:"expiresAt,omitempty"`
	DaysLeft   int    `json:"daysLeft,omitempty"`
}

// CliJailVexPayload carries the statements the CLI feeds to
// internal/triage.GenerateOpenVEX and GenerateCDXVEX.
//
// Justification is never empty on a statement the server sends, and the CLI
// asserts that rather than trusting it: GenerateOpenVEX rewrites a statement
// with a fixed version and an empty justification to status not_affected, which
// is the exact inverse of what a jail asserts.
type CliJailVexPayload struct {
	DocumentID string                `json:"documentId"`
	Author     string                `json:"author"`
	Statements []CliJailVexStatement `json:"statements"`
}

type CliJailVexStatement struct {
	VulnID           string `json:"vulnId"`
	Package          string `json:"package,omitempty"`
	Ecosystem        string `json:"ecosystem,omitempty"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	FixedVersion     string `json:"fixedVersion,omitempty"`
	Status           string `json:"status"`
	Justification    string `json:"justification"`
	ActionStatement  string `json:"actionStatement,omitempty"`
	Severity         string `json:"severity,omitempty"`
	RuleUuid         string `json:"ruleUuid,omitempty"`
}

// CliJailSarifPayload is the non-vulnerability half — EOL, GOAL and HYGIENE.
// Written to disk and never posted back: the server records a ScannerRun on any
// SARIF body, so a jail that uploaded would manufacture the coverage the next
// jail measures freshness against.
type CliJailSarifPayload struct {
	Rules   []CliJailSarifRule   `json:"rules"`
	Results []CliJailSarifResult `json:"results"`
}

type CliJailSarifRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	HelpURI     string   `json:"helpUri,omitempty"`
	Severity    string   `json:"severity"`
	Level       string   `json:"level"`
	Tags        []string `json:"tags,omitempty"`
}

type CliJailSarifResult struct {
	RuleID      string `json:"ruleId"`
	Message     string `json:"message"`
	ArtifactURI string `json:"artifactUri"`
	Severity    string `json:"severity"`
	Level       string `json:"level"`
	StartLine   int    `json:"startLine,omitempty"`
}

type CliJailSummary struct {
	RulesEvaluated int `json:"rulesEvaluated"`
	Breaches       int `json:"breaches"`
	Warnings       int `json:"warnings"`
	Indeterminate  int `json:"indeterminate"`
	Skipped        int `json:"skipped"`
	Exempted       int `json:"exempted"`
}

// CliJailExemptRequest is the payload for POST /v2/cli.jail-exempt.
type CliJailExemptRequest struct {
	RuleUuid  string `json:"ruleUuid,omitempty"`
	Repo      string `json:"repo,omitempty"`
	Reason    string `json:"reason"`
	ExpiresAt int64  `json:"expiresAt,omitempty"`

	Deactivate       string `json:"deactivate,omitempty"`
	DeactivateReason string `json:"deactivateReason,omitempty"`
}

type CliJailExemptResponse struct {
	Exemption *CliJailExemptionApplied `json:"exemption,omitempty"`
	Action    string                   `json:"action"`
}

// CliJail evaluates the org's jail policy for this repo.
//
// Uses the context variant so a gate honours the pipeline's deadline rather than
// the client's 180s default, and so a 429 or 503 surfaces as a typed
// *CliAPIError the caller can decide about instead of an opaque string.
func (c *Client) CliJail(ctx context.Context, env CliEnv, req CliJailRequest) (*CliResponse[CliJailResponse], error) {
	return cliPostWithEnvContext[CliJailResponse](ctx, c, "cli.jail", env, req)
}

// CliJailExempt creates or retires a jail exemption.
func (c *Client) CliJailExempt(ctx context.Context, env CliEnv, req CliJailExemptRequest) (*CliResponse[CliJailExemptResponse], error) {
	return cliPostWithEnvContext[CliJailExemptResponse](ctx, c, "cli.jail-exempt", env, req)
}
