package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// ─────────────────────────────────────────────────────────────────────────
// jail_test.go — runJailPipeline against a mock server.
//
// runJailPipeline is the jail capability's single entry point: the bare
// command, explain, list, exempt, and `scan --jail` all reach the gate through
// it. Testing it directly therefore covers every caller.
// ─────────────────────────────────────────────────────────────────────────

// jailMockServer stands in for /v2/cli.jail, capturing the request it received
// so the test can assert what the CLI actually sent.
type jailMockServer struct {
	*httptest.Server
	LastPath    string
	LastEnv     vdb.CliEnv
	LastPayload vdb.CliJailRequest
	LastExempt  vdb.CliJailExemptRequest
}

func newJailMockServer(t *testing.T, respond func(*testing.T) any) *jailMockServer {
	t.Helper()
	m := &jailMockServer{}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.LastPath = r.URL.Path

		body, _ := io.ReadAll(r.Body)
		var envelope struct {
			Env     vdb.CliEnv      `json:"env"`
			Payload json.RawMessage `json:"payload"`
		}
		_ = json.Unmarshal(body, &envelope)
		m.LastEnv = envelope.Env

		switch {
		case r.URL.Path == "/v2/cli.jail-exempt":
			_ = json.Unmarshal(envelope.Payload, &m.LastExempt)
		default:
			_ = json.Unmarshal(envelope.Payload, &m.LastPayload)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"meta": map[string]any{"tier": "pro", "endpointVersion": "2.0"},
			"data": respond(t),
		})
	}))
	t.Cleanup(m.Close)
	return m
}

// withJailMock points the CLI at the mock and gives it a scratch working
// directory, so a test never writes an artefact into the repository it runs in.
func withJailMock(t *testing.T, m *jailMockServer) string {
	t.Helper()
	t.Setenv("VULNETIX_API_URL", m.URL)

	dir := t.TempDir()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
	return dir
}

func jailResponse(verdict string, exitCode int, rules ...vdb.CliJailRuleVerdict) map[string]any {
	summary := vdb.CliJailSummary{RulesEvaluated: len(rules)}
	for _, r := range rules {
		switch r.State {
		case vdb.JailStateBreach:
			summary.Breaches++
		case vdb.JailStateIndeterminate:
			summary.Indeterminate++
		case vdb.JailStateWarn:
			summary.Warnings++
		}
	}
	return map[string]any{
		"verdict":     verdict,
		"exitCode":    exitCode,
		"evaluatedAt": time.Now().UnixMilli(),
		"scope": map[string]any{
			"repo": "acme/widget", "branch": "main",
			"repoSource": "git", "branchSource": "git",
		},
		"freshness": map[string]any{"categories": []any{}},
		"rules":     rules,
		"summary":   summary,
	}
}

// TestJailPipelineVerdictToExitCode pins the mapping from a server verdict onto
// the process exit code the CLI will produce.
func TestJailPipelineVerdictToExitCode(t *testing.T) {
	cases := []struct {
		name     string
		verdict  string
		exitCode int
		want     int
	}{
		{"clear", vdb.JailVerdictClear, 0, ExitOK},
		{"jailed", vdb.JailVerdictJailed, 1, ExitFailure},
		{"indeterminate", vdb.JailVerdictIndeterminate, 3, ExitIndeterminate},
		{"no policy", vdb.JailVerdictNoPolicy, 0, ExitOK},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newJailMockServer(t, func(*testing.T) any {
				return jailResponse(tc.verdict, tc.exitCode)
			})
			withJailMock(t, m)

			result, err := runJailPipeline(context.Background(), JailRunOptions{Mode: jailModeAssess})
			if err != nil {
				t.Fatalf("runJailPipeline: %v", err)
			}
			if result.ExitCode != tc.want {
				t.Fatalf("exit = %d, want %d", result.ExitCode, tc.want)
			}
			if m.LastPath != "/v2/cli.jail" {
				t.Fatalf("posted to %q, want /v2/cli.jail", m.LastPath)
			}
		})
	}
}

// TestJailPipelineNoFailForcesZero pins the adoption escape hatch: report
// everything, gate nothing.
func TestJailPipelineNoFailForcesZero(t *testing.T) {
	m := newJailMockServer(t, func(*testing.T) any {
		return jailResponse(vdb.JailVerdictJailed, 1, vdb.CliJailRuleVerdict{
			RuleUuid: "r1", Kind: "VULN", Label: "no criticals",
			State: vdb.JailStateBreach, Reason: "3 open criticals",
		})
	})
	withJailMock(t, m)

	result, err := runJailPipeline(context.Background(), JailRunOptions{
		Mode:   jailModeAssess,
		NoFail: true,
	})
	if err != nil {
		t.Fatalf("runJailPipeline: %v", err)
	}
	if result.ExitCode != ExitOK {
		t.Fatalf("exit = %d, want 0 under --no-fail", result.ExitCode)
	}
	// The verdict itself must survive: --no-fail suppresses the gate, not the
	// report. An operator has to still see what would have failed.
	if result.Response.Verdict != vdb.JailVerdictJailed {
		t.Fatalf("verdict = %q, want jailed — --no-fail must not rewrite the verdict", result.Response.Verdict)
	}
}

// TestJailPipelineWritesArtefactsOnARedGate pins that the evidence lands
// exactly when somebody needs it most.
func TestJailPipelineWritesArtefactsOnARedGate(t *testing.T) {
	m := newJailMockServer(t, func(*testing.T) any {
		resp := jailResponse(vdb.JailVerdictJailed, 1, vdb.CliJailRuleVerdict{
			RuleUuid: "r1", Kind: "VULN", Label: "sla", State: vdb.JailStateBreach,
		})
		resp["vex"] = map[string]any{
			"documentId": "urn:test",
			"author":     "Vulnetix",
			"statements": []map[string]any{{
				"vulnId":        "CVE-2024-0001",
				"package":       "left-pad",
				"ecosystem":     "npm",
				"status":        "affected",
				"justification": "remediation_window_exceeded",
			}},
		}
		resp["sarif"] = map[string]any{
			"rules": []map[string]any{{
				"id": "VULNETIX-JAIL-EOL-x", "name": "eol", "description": "d",
				"severity": "high", "level": "error",
			}},
			"results": []map[string]any{{
				"ruleId": "VULNETIX-JAIL-EOL-x", "message": "m",
				"artifactUri": ".", "severity": "high", "level": "error",
			}},
		}
		return resp
	})
	dir := withJailMock(t, m)

	result, err := runJailPipeline(context.Background(), JailRunOptions{
		Mode:       jailModeAssess,
		WriteVex:   true,
		WriteSarif: true,
		VexPath:    filepath.Join(dir, "jail.vex.json"),
		SarifPath:  filepath.Join(dir, "jail.sarif"),
		VexFormat:  "openvex",
	})
	if err != nil {
		t.Fatalf("runJailPipeline: %v", err)
	}
	if len(result.Artefacts) != 2 {
		t.Fatalf("artefacts = %v, want 2", result.Artefacts)
	}
	for _, p := range result.Artefacts {
		if _, statErr := os.Stat(p); statErr != nil {
			t.Fatalf("artefact %s not written: %v", p, statErr)
		}
	}
	if !m.LastPayload.IncludeVex || !m.LastPayload.IncludeSarif {
		t.Fatal("the CLI did not ask the server for artefacts it intended to write")
	}
}

// TestJailPipelineRejectsScopeOverrideOnAssess pins the one place a client could
// otherwise point its own gate at a clean repository.
func TestJailPipelineRejectsScopeOverrideOnAssess(t *testing.T) {
	m := newJailMockServer(t, func(*testing.T) any {
		return jailResponse(vdb.JailVerdictClear, 0)
	})
	withJailMock(t, m)

	for _, opts := range []JailRunOptions{
		{Mode: jailModeAssess, Repo: "someone/else"},
		{Mode: jailModeAssess, Branch: "a-clean-branch"},
	} {
		_, err := runJailPipeline(context.Background(), opts)
		if err == nil {
			t.Fatalf("a scope override on assess was accepted: %+v", opts)
		}
		if ExitCode(err) != ExitUsage {
			t.Fatalf("exit = %d, want %d for a usage error", ExitCode(err), ExitUsage)
		}
	}

	// The same overrides ARE honoured on the inspection modes.
	result, err := runJailPipeline(context.Background(), JailRunOptions{
		Mode: jailModeExplain, Repo: "acme/other", Branch: "release",
	})
	if err != nil {
		t.Fatalf("runJailPipeline(explain): %v", err)
	}
	if result == nil {
		t.Fatal("explain returned no result")
	}
	if m.LastPayload.Repo != "acme/other" || m.LastPayload.Branch != "release" {
		t.Fatalf("overrides not forwarded: repo=%q branch=%q", m.LastPayload.Repo, m.LastPayload.Branch)
	}
}

// TestJailPipelineValidatesBeforeAnyNetworkWork pins that a local mistake is
// caught before a round trip, the way --dry-run is handled across the scan
// family. A pipeline that misconfigured the gate should learn immediately.
func TestJailPipelineValidatesBeforeAnyNetworkWork(t *testing.T) {
	m := newJailMockServer(t, func(t *testing.T) any {
		t.Error("the server was contacted despite an invalid option")
		return jailResponse(vdb.JailVerdictClear, 0)
	})
	withJailMock(t, m)

	cases := []struct {
		name string
		opts JailRunOptions
	}{
		{"unknown mode", JailRunOptions{Mode: "demolish"}},
		{"bad vex format", JailRunOptions{Mode: jailModeAssess, VexFormat: "spdx"}},
		{"bad on-stale", JailRunOptions{Mode: jailModeAssess, OnStale: "maybe"}},
		{"negative staleness", JailRunOptions{Mode: jailModeAssess, StalenessDays: -1}},
		{"negative lookback", JailRunOptions{Mode: jailModeAssess, MaxLookbackDays: -1}},
		{"bad output", JailRunOptions{Mode: jailModeAssess, Output: "yaml"}},
		{"exempt without a reason", JailRunOptions{Mode: jailModeExempt}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := runJailPipeline(context.Background(), tc.opts)
			if err == nil {
				t.Fatal("invalid options were accepted")
			}
			if ExitCode(err) != ExitUsage {
				t.Fatalf("exit = %d, want %d", ExitCode(err), ExitUsage)
			}
		})
	}
}

// TestJailPipelineForwardsKnownSnapshots pins the replica-lag hint that makes
// `scan --jail` deterministic.
func TestJailPipelineForwardsKnownSnapshots(t *testing.T) {
	m := newJailMockServer(t, func(*testing.T) any {
		return jailResponse(vdb.JailVerdictClear, 0)
	})
	withJailMock(t, m)

	_, err := runJailPipeline(context.Background(), JailRunOptions{
		Mode:               jailModeAssess,
		KnownSnapshotUuids: []string{"snap-a", "snap-b"},
	})
	if err != nil {
		t.Fatalf("runJailPipeline: %v", err)
	}
	if len(m.LastPayload.KnownSnapshotUuids) != 2 {
		t.Fatalf("knownSnapshotUuids = %v, want 2", m.LastPayload.KnownSnapshotUuids)
	}
}

// TestJailPipelineExempt pins the write half.
func TestJailPipelineExempt(t *testing.T) {
	m := newJailMockServer(t, func(*testing.T) any {
		return map[string]any{
			"action": "created",
			"exemption": map[string]any{
				"uuid": "ex-1", "ruleUuid": "r1", "reason": "tracked in JIRA-42",
				"approvedBy": "someone", "expiresAt": time.Now().Add(24 * time.Hour).UnixMilli(),
			},
		}
	})
	withJailMock(t, m)

	result, err := runJailPipeline(context.Background(), JailRunOptions{
		Mode:           jailModeExempt,
		ExemptRuleUuid: "r1",
		ExemptReason:   "tracked in JIRA-42",
		ExemptExpires:  24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("runJailPipeline: %v", err)
	}
	if m.LastPath != "/v2/cli.jail-exempt" {
		t.Fatalf("posted to %q, want /v2/cli.jail-exempt", m.LastPath)
	}
	if m.LastExempt.Reason != "tracked in JIRA-42" || m.LastExempt.RuleUuid != "r1" {
		t.Fatalf("exempt request = %+v", m.LastExempt)
	}
	if m.LastExempt.ExpiresAt == 0 {
		t.Fatal("--expires did not become an absolute expiry")
	}
	if result.Exemption == nil || result.Exemption.Action != "created" {
		t.Fatalf("result = %+v", result.Exemption)
	}
	// An exemption is an administrative action, never a gate.
	if result.ExitCode != ExitOK {
		t.Fatalf("exit = %d, want 0", result.ExitCode)
	}
}

// TestJailPipelineDeactivateNeedsNoReason pins that retiring a waiver does not
// require the create-path reason.
func TestJailPipelineDeactivateNeedsNoReason(t *testing.T) {
	m := newJailMockServer(t, func(*testing.T) any {
		return map[string]any{"action": "deactivated"}
	})
	withJailMock(t, m)

	if _, err := runJailPipeline(context.Background(), JailRunOptions{
		Mode:             jailModeExempt,
		ExemptDeactivate: "ex-1",
	}); err != nil {
		t.Fatalf("runJailPipeline: %v", err)
	}
	if m.LastExempt.Deactivate != "ex-1" {
		t.Fatalf("deactivate = %q, want ex-1", m.LastExempt.Deactivate)
	}
}

// TestJailPipelineSendsCIContext pins the env.CI fix from the gate's side: a
// request made inside a runner must carry the CI identity, because the branch
// key the server resolves depends on it and a detached HEAD carries none.
func TestJailPipelineSendsCIContext(t *testing.T) {
	m := newJailMockServer(t, func(*testing.T) any {
		return jailResponse(vdb.JailVerdictClear, 0)
	})
	withJailMock(t, m)

	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/widget")
	t.Setenv("GITHUB_REF_NAME", "main")
	t.Setenv("GITHUB_HEAD_REF", "feature/x")
	t.Setenv("GITHUB_SHA", "deadbeef")

	if _, err := runJailPipeline(context.Background(), JailRunOptions{Mode: jailModeAssess}); err != nil {
		t.Fatalf("runJailPipeline: %v", err)
	}
	if m.LastEnv.CI == nil {
		t.Fatal("no CI context was sent from inside a runner; the server would resolve branch \"(unknown)\"")
	}
	if m.LastEnv.CI.Repository != "acme/widget" {
		t.Fatalf("CI repository = %q", m.LastEnv.CI.Repository)
	}
	if m.LastEnv.CI.HeadRef != "feature/x" {
		t.Fatalf("CI head ref = %q", m.LastEnv.CI.HeadRef)
	}
}

// TestCliEnvHasNoCIOutsideARunner pins the other half: a workstation scan must
// not invent a CI block.
func TestCliEnvHasNoCIOutsideARunner(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("GITHUB_RUN_ID", "")

	if env := envForCliWithGit(nil); env.CI != nil {
		t.Fatalf("CI context = %+v outside a runner, want nil", env.CI)
	}
	if env := buildCliEnv(nil, nil); env.CI != nil {
		t.Fatalf("CI context = %+v outside a runner, want nil", env.CI)
	}
}

// TestBuildCliEnvCollectsCIInsideARunner pins the SCA path's half of the fix.
func TestBuildCliEnvCollectsCIInsideARunner(t *testing.T) {
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_REPOSITORY", "acme/widget")
	t.Setenv("GITHUB_REF_NAME", "main")

	env := buildCliEnv(nil, nil)
	if env.CI == nil {
		t.Fatal("buildCliEnv sent no CI context from inside a runner")
	}
	if env.CI.RefName != "main" {
		t.Fatalf("ref name = %q, want main", env.CI.RefName)
	}
}

// TestFinalizedSnapshotList pins ordering, dedup and blank handling for the
// replica-lag hint.
func TestFinalizedSnapshotList(t *testing.T) {
	got := finalizedSnapshotList("sca-1", map[string]string{
		"secrets": "sarif-secrets",
		"sast":    "sarif-sast",
		"iac":     "",
		"dupe":    "sca-1",
	})
	want := []string{"sca-1", "sarif-sast", "sarif-secrets"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}

	if n := len(finalizedSnapshotList("", nil)); n != 0 {
		t.Fatalf("empty input produced %d entries", n)
	}
}

// TestJailIndeterminateErrorPrecedence pins that a breach beats an unknown.
//
// A definite violation on data we hold is a fact; an unknown elsewhere does not
// make it less true. Reporting exit 3 alongside a real breach would send the
// operator to inspect their CI configuration instead of the vulnerability.
func TestJailIndeterminateErrorPrecedence(t *testing.T) {
	breach := []GateBreach{{Gate: "jail:x", Count: 1, Message: "breached"}}

	if err := jailIndeterminateError(breach, true); err != nil {
		t.Fatal("an indeterminate error was returned alongside a breach; exit 3 would mask exit 1")
	}
	if err := jailIndeterminateError(nil, false); err != nil {
		t.Fatal("an indeterminate error was returned for a clean run")
	}
	err := jailIndeterminateError(nil, true)
	if err == nil {
		t.Fatal("no error for an indeterminate run with nothing else to report")
	}
	if ExitCode(err) != ExitIndeterminate {
		t.Fatalf("exit = %d, want %d", ExitCode(err), ExitIndeterminate)
	}
}
