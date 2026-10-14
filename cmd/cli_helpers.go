package cmd

// Shared CLI helpers for migrating vdb subcommands from the legacy granular
// /v2/* endpoints to the new dedicated /v2/cli.* surface. Each subcommand
// helper tries the cli.* endpoint first and falls back to its legacy
// counterpart on 4xx so deploys can roll out without breaking running CLIs.
// Operational chatter is gated behind `verbose` to keep default output
// succinct.

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/internal/ghactx"
	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// envForCli builds the standard CliEnv that ships with every cli.* call,
// deriving git context from the current working directory. Used by the vdb
// query subcommands (vuln, exploits, …) which have no scan target.
func envForCli() vdb.CliEnv {
	return envForCliWithGit(nil)
}

// envForCliWithGit builds the standard CliEnv but uses the supplied git context
// (collected from the scan's --path target) rather than the CWD. Scan
// subcommands that persist findings under a repo identity (SAST/Secrets/IaC/
// Containers/License) MUST use this so the snapshot's repo name, branch, remote
// and root reflect the scanned path, not wherever the CLI was invoked from. A
// nil git falls back to the CWD (envForCli's behaviour).
func envForCliWithGit(git *gitctx.GitContext) vdb.CliEnv {
	env := vdb.CliEnv{
		CliVersion: version,
		Commit:     commit,
		BuildDate:  buildDate,
		Deployment: deploymentEnv(),
	}
	if sys := gitctx.CollectSystemInfo(); sys != nil {
		env.OS = sys.OS
		env.Arch = sys.Arch
		env.Platform = sys.OS
		env.Hostname = sys.Hostname
		env.Shell = sys.Shell
	}
	if git == nil {
		if cwd, _ := os.Getwd(); cwd != "" {
			git = cwdGitContext(cwd)
		}
	}
	if git != nil {
		env.Git = &vdb.CliGitContext{
			Branch:   git.CurrentBranch,
			Commit:   git.CurrentCommit,
			Author:   git.HeadCommitAuthor,
			Remotes:  git.RemoteURLs,
			Dirty:    git.IsDirty,
			RepoRoot: git.RepoRootPath,
		}
	}
	if env.CI == nil {
		env.CI = ciContextForCli()
	}
	return env
}

// ciContextForCli collects the CI identity that ships with every cli.* request.
//
// Free tier only: environment variables plus the GITHUB_EVENT_PATH payload
// already on disk. No network, no token. Returns nil outside a runner.
//
// This exists because a CI checkout is a detached HEAD, so gitctx reads
// "HEAD (detached)" for the branch in every runner. The server already prefers
// the CI fields over the local checkout — findingGitContext and the console's
// branch key both put ciHeadRef and ciRefName ahead of gitBranch — but until
// this call was added, only `gha upload` ever populated them. Every other cli.*
// request from inside GitHub Actions therefore landed under branch "(unknown)",
// which is why repo/branch filtering across the console has been thin for
// pipeline scans.
//
// `gha upload` keeps its own richer call (ghactx.Options{Lookup: …}); that is
// the only path allowed to spend GitHub REST calls, and the guard on env.CI
// above means it is never clobbered by this one.
func ciContextForCli() *vdb.CliCIContext {
	return ghactx.Collect(context.Background(), ghactx.Options{NoAPI: true})
}

// newCliClient returns a /v2 vdb client configured for cli.* endpoints.
// It shares the same auth configuration as the legacy clients. Individual
// cli.* callers may tighten timeouts or bypass generic retries when a bounded
// request path is more appropriate.
func newCliClient() *vdb.Client {
	c := newEnrichmentClient()
	if c == nil {
		return nil
	}
	c.APIVersion = "/v2"
	if c.HTTPClient != nil {
		c.HTTPClient.Timeout = 180 * time.Second
	}
	return c
}

// isCli404 reports whether err looks like a route-missing error from the
// upstream API. Used to decide between the cli.* primary path and the
// legacy fallback.
func isCli404(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "404") || strings.Contains(s, "not found")
}

// logCliOp emits a single-line operation note when --verbose is on; silent
// otherwise. Use for "calling /v2/cli.x …" style chatter.
func logCliOp(format string, a ...any) {
	if !verbose {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", a...)
}

// extractByID lifts data[key][id] out of the standard cli.* batched envelope
// shape ({"<key>": {"<id>": <payload>}}). Returns nil when shape is unexpected
// so callers can fall back.
func extractByID(data map[string]any, key, id string) any {
	if data == nil {
		return nil
	}
	bag, ok := data[key].(map[string]any)
	if !ok {
		return nil
	}
	return bag[id]
}

// asMap coerces an `any` to a non-nil map[string]any, returning the original
// data wrapped under "data" when the payload is something else (e.g. an
// array). Callers feed the result into legacy display.Render* helpers which
// expect a map shape.
func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok && m != nil {
		return m
	}
	return map[string]any{"data": v}
}

// ─── Per-subcommand call wrappers ─────────────────────────────────────────
//
// Each helper tries the dedicated /v2/cli.<x> endpoint first and falls back
// to the legacy granular /v2/* endpoint on 404 / unknown route. Once the API
// deploy is verified live, the legacy fallback can be removed and these
// helpers reduced to a single Cli<X> call.

func callWorkarounds(client *vdb.Client, id string) (map[string]any, error) {
	if c := newCliClient(); c != nil {
		if resp, err := c.CliWorkarounds(envForCli(), []string{id}); err == nil {
			if per := extractByID(resp.Data, "workaroundsByVuln", id); per != nil {
				return workaroundsResult(id, per), nil
			}
			logCliOp("  cli.workarounds had no entry for %s, trying /v2/vuln/%s/workarounds", id, id)
		} else if !isCli404(err) {
			logCliOp("  cli.workarounds errored (%v), falling back to legacy", err)
		}
	}
	m, err := client.V2Workarounds(id)
	if err != nil {
		if isCli404(err) {
			return workaroundsResult(id, nil), nil
		}
		return nil, err
	}
	return withIdentifier(m, id), nil
}

func callAdvisories(client *vdb.Client, id string) (map[string]any, error) {
	if c := newCliClient(); c != nil {
		if resp, err := c.CliAdvisories(envForCli(), []string{id}); err == nil {
			if per := extractByID(resp.Data, "advisoriesByVuln", id); per != nil {
				return advisoriesResult(id, per), nil
			}
			// The batched endpoint answered, but with nothing for this id. That is
			// not the same as "there are none": ask the per-vulnerability endpoint
			// before saying so, instead of returning the empty envelope as though
			// it were the answer.
			logCliOp("  cli.advisories had no entry for %s, trying /v2/vuln/%s/advisories", id, id)
		} else if !isCli404(err) {
			logCliOp("  cli.advisories errored (%v), falling back to legacy", err)
		}
	}
	m, err := client.V2Advisories(id)
	if err != nil {
		if isCli404(err) {
			return advisoriesResult(id, nil), nil
		}
		return nil, err
	}
	return withIdentifier(m, id), nil
}

// withIdentifier makes sure a per-vulnerability result says which vulnerability it
// is for. A renderer that prints "Advisories for" and then nothing has no way to
// tell the reader what was looked up.
func withIdentifier(m map[string]any, id string) map[string]any {
	if m == nil {
		m = map[string]any{}
	}
	if s, _ := m["identifier"].(string); s == "" {
		m["identifier"] = id
	}
	return m
}

// advisoriesResult shapes a cli.advisories payload into what the renderer and
// JSON consumers read. The batched endpoint returns reference rows
// ({url, referenceSource, tags}); the per-vulnerability endpoint returns
// {identifier, advisories: [{id, title, url, source}]}. Both land in the second.
func advisoriesResult(id string, per any) map[string]any {
	out := map[string]any{"identifier": id, "advisories": []any{}}
	switch v := per.(type) {
	case map[string]any:
		// Already per-vulnerability shaped.
		return withIdentifier(v, id)
	case []any:
		advs := make([]any, 0, len(v))
		for _, row := range v {
			r, ok := row.(map[string]any)
			if !ok {
				continue
			}
			adv := map[string]any{"url": r["url"], "source": r["referenceSource"]}
			if tags, ok := r["tags"]; ok && tags != nil {
				adv["tags"] = tags
			}
			advs = append(advs, adv)
		}
		out["advisories"] = advs
	}
	return out
}

// workaroundsResult is advisoriesResult's counterpart for workarounds.
func workaroundsResult(id string, per any) map[string]any {
	out := map[string]any{"identifier": id, "workarounds": []any{}}
	switch v := per.(type) {
	case map[string]any:
		return withIdentifier(v, id)
	case []any:
		out["workarounds"] = v
	}
	return out
}

func callCweGuidance(client *vdb.Client, id string) (map[string]any, error) {
	if c := newCliClient(); c != nil {
		// cli.cwe-guidance is keyed by CWE id; for CVE→CWE fan-out we still
		// need the legacy plus the new pivot.
		if resp, err := c.CliCweGuidance(envForCli(), []string{id}); err == nil {
			if !cliAnswerPending(resp.Data, "guidanceByCwe") {
				return resp.Data, nil
			}
			logCliOp("  cli.cwe-guidance returned a placeholder for %s, trying /v2/vuln/%s/cwe-guidance", id, id)
		} else if !isCli404(err) {
			logCliOp("  cli.cwe-guidance errored (%v), falling back to legacy", err)
		}
	}
	return client.V2CweGuidance(id)
}

func callScorecard(client *vdb.Client, id string) (map[string]any, error) {
	if c := newCliClient(); c != nil {
		// scorecard is purl-keyed; legacy was CVE-keyed. Use id as a generic
		// hint until the server cuts over to PURL-keyed scorecards.
		if resp, err := c.CliScorecard(envForCli(), []string{id}); err == nil {
			if !cliAnswerPending(resp.Data, "scorecardByPurl") {
				return resp.Data, nil
			}
			logCliOp("  cli.scorecard returned a placeholder for %s, trying /v2/vuln/%s/scorecard", id, id)
		} else if !isCli404(err) {
			logCliOp("  cli.scorecard errored (%v), falling back to legacy", err)
		}
	}
	return client.V2Scorecard(id)
}

func callRemediation(client *vdb.Client, id string, p vdb.V2RemediationParams) (map[string]any, error) {
	if c := newCliClient(); c != nil {
		ctx := map[string]string{
			"ecosystem":      p.Ecosystem,
			"packageName":    p.PackageName,
			"vendor":         p.Vendor,
			"product":        p.Product,
			"purl":           p.Purl,
			"currentVersion": p.CurrentVersion,
			"packageManager": p.PackageManager,
			"containerImage": p.ContainerImage,
			"os":             p.OS,
			"registry":       p.Registry,
		}
		req := vdb.CliRemediationRequest{IDs: []string{id}, Context: ctx}
		if resp, err := c.CliRemediation(envForCli(), req); err == nil {
			if per := extractByID(resp.Data, "planByVuln", id); per != nil {
				return asMap(per), nil
			}
			// No entry for this id: ask the per-vulnerability endpoint rather than
			// returning the empty batched envelope as the answer.
			logCliOp("  cli.remediation had no entry for %s, trying the legacy plan endpoint", id)
		} else if !isCli404(err) {
			logCliOp("  cli.remediation errored (%v), falling back to legacy", err)
		}
	}
	return client.V2RemediationPlan(id, p)
}

func callTriage(client *vdb.Client, params vdb.TriageParams) (map[string]any, error) {
	if c := newCliClient(); c != nil {
		sev := []string{}
		if params.Severity != "" {
			sev = strings.Split(params.Severity, ",")
		}
		req := vdb.CliTriageRequest{
			Severity: sev,
			MinCvss:  derefFloat(params.MinCvss),
			MinEpss:  derefFloat(params.MinEpss),
			Limit:    params.Limit,
			Offset:   params.Offset,
			Since:    params.Since,
		}
		if params.InKev == "true" {
			t := true
			req.InKev = &t
		} else if params.InKev == "false" {
			f := false
			req.InKev = &f
		}
		if resp, err := c.CliTriage(envForCli(), req); err == nil {
			return resp.Data, nil
		} else if !isCli404(err) {
			logCliOp("  cli.triage errored (%v), falling back to legacy", err)
		}
	}
	return client.V2Triage(params)
}

func derefFloat(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}

// warnOutputExtension warns when --output-file names an extension that
// contradicts the content the command always writes. cbom/aibom emit
// CycloneDX and malscan emits SARIF regardless of the filename, so a
// mismatch silently feeds the wrong parser downstream.
//
// This warns rather than errors: the path is the user's to choose, and a
// pipeline that already depends on an odd name must keep working.
func warnOutputExtension(path, wantSuffix string) {
	if path == "" {
		return
	}
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, wantSuffix) {
		return
	}
	// A bare `.cdx` is an accepted CycloneDX spelling.
	if wantSuffix == ".cdx.json" && strings.HasSuffix(lower, ".cdx") {
		return
	}
	fmt.Fprintf(os.Stderr, "warning: %s does not end in %s, but this command always writes %s content\n",
		path, wantSuffix, strings.TrimPrefix(wantSuffix, "."))
}

// cliAnswerPending reports whether a cli.* response is a placeholder rather than
// an answer: the keyed bag is empty, or the server says its backend is not wired
// up yet. Returning one of those as the result prints a header with nothing under
// it, so the caller falls through to the per-vulnerability endpoint instead.
func cliAnswerPending(data map[string]any, key string) bool {
	if note, _ := data["note"].(string); strings.Contains(strings.ToLower(note), "pending") {
		return true
	}
	bag, ok := data[key].(map[string]any)
	return !ok || len(bag) == 0
}

// cwdGitContexts holds the git context of each working directory envForCli has
// read, once per process. A scan sends several cli.* requests (suppressions,
// licences, ...), often at once, and each used to run git status over the
// whole working directory again; nothing a command does between them changes
// the repository.
var cwdGitContexts sync.Map // dir -> func() *gitctx.GitContext

func cwdGitContext(dir string) *gitctx.GitContext {
	f, _ := cwdGitContexts.LoadOrStore(dir, sync.OnceValue(func() *gitctx.GitContext { return gitctx.Collect(dir) }))
	return f.(func() *gitctx.GitContext)()
}
