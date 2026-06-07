package cmd

// Shared CLI helpers for migrating vdb subcommands from the legacy granular
// /v2/* endpoints to the new dedicated /v2/cli.* surface. Each subcommand
// helper tries the cli.* endpoint first and falls back to its legacy
// counterpart on 4xx so deploys can roll out without breaking running CLIs.
// Operational chatter is gated behind `verbose` to keep default output
// succinct.

import (
	"fmt"
	"os"
	"strings"
	"time"

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
			git = gitctx.Collect(cwd)
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
	return env
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
				return asMap(per), nil
			}
			return resp.Data, nil
		} else if !isCli404(err) {
			logCliOp("  cli.workarounds errored (%v), falling back to legacy", err)
		}
	}
	return client.V2Workarounds(id)
}

func callAdvisories(client *vdb.Client, id string) (map[string]any, error) {
	if c := newCliClient(); c != nil {
		if resp, err := c.CliAdvisories(envForCli(), []string{id}); err == nil {
			if per := extractByID(resp.Data, "advisoriesByVuln", id); per != nil {
				return asMap(per), nil
			}
			return resp.Data, nil
		} else if !isCli404(err) {
			logCliOp("  cli.advisories errored (%v), falling back to legacy", err)
		}
	}
	return client.V2Advisories(id)
}

func callCweGuidance(client *vdb.Client, id string) (map[string]any, error) {
	if c := newCliClient(); c != nil {
		// cli.cwe-guidance is keyed by CWE id; for CVE→CWE fan-out we still
		// need the legacy plus the new pivot.
		if resp, err := c.CliCweGuidance(envForCli(), []string{id}); err == nil {
			return resp.Data, nil
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
			return resp.Data, nil
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
			return resp.Data, nil
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
