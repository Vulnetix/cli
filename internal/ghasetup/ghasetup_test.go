package ghasetup

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestCatalogLoads(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Tools) < 12 {
		t.Errorf("catalog has %d tools; the production pipeline alone runs 12", len(c.Tools))
	}

	seen := map[string]bool{}
	for _, tool := range c.Tools {
		if seen[tool.ID] {
			t.Errorf("duplicate tool id %q; ids key the workflow jobs and must be unique", tool.ID)
		}
		seen[tool.ID] = true

		if tool.Artifact == "" || len(tool.Paths) == 0 || len(tool.Steps) == 0 {
			t.Errorf("%s: needs an artifact name, at least one path, and at least one step", tool.ID)
		}
		// The job id becomes a YAML key and a `needs:` entry.
		if !regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`).MatchString(tool.ID) {
			t.Errorf("%s: id must be a valid workflow job key", tool.ID)
		}
		for _, s := range tool.Steps {
			if (s.Uses == "") == (s.Run == "") {
				t.Errorf("%s: step %q must have exactly one of uses or run", tool.ID, s.Name)
			}
		}
	}
}

// Every scanner the production pipeline runs must be settable up by this
// command, or the docs generated from this catalog would omit a tool people
// are already running.
func TestCatalogCoversTheProductionPipeline(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{
		"gosec", "osv-scanner", "semgrep", "syft", "trivy-fs", "trivy-config",
		"grype", "checkov", "kics", "tfsec", "terrascan", "zizmor",
	} {
		if _, ok := c.Find(id); !ok {
			t.Errorf("catalog is missing %q, which scanners.yml runs today", id)
		}
	}
}

// A tool that writes SARIF through a shell redirect must validate the result.
// `tool > out.sarif` leaves a zero-byte file when the tool fails, and
// if-no-files-found cannot catch that because the file exists — it then gets
// published as a scan report. This is the exact defect that hid a broken
// pipeline in production.
func TestShellRedirectsValidateTheirOutput(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	redirect := regexp.MustCompile(`>\s*\S*\.sarif`)

	for _, tool := range c.Tools {
		for _, s := range tool.Steps {
			if s.Run == "" || !redirect.MatchString(s.Run) {
				continue
			}
			if !strings.Contains(s.Run, "jq -e") {
				t.Errorf("%s redirects into a .sarif file without validating it; "+
					"a failed run would publish a zero-byte report", tool.ID)
			}
		}
	}
}

// Third-party scanners are pinned so a scan cannot change shape without a
// change here.
func TestThirdPartyStepsArePinned(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range c.Tools {
		for _, s := range tool.Steps {
			if s.Uses != "" && !strings.Contains(s.Uses, "@") {
				t.Errorf("%s: action %q is not pinned", tool.ID, s.Uses)
			}
			if s.Uses != "" && strings.HasSuffix(s.Uses, "@master") {
				t.Errorf("%s: action %q tracks a branch", tool.ID, s.Uses)
			}
			if strings.Contains(s.Run, ":latest") {
				t.Errorf("%s: run step uses a :latest container tag", tool.ID)
			}
		}
	}
}

// The Vulnetix CLI is deliberately NOT pinned. A pinned CLI is how a fleet ends
// up spread across three versions with nobody noticing.
func TestRenderInstallsTheCliUnpinned(t *testing.T) {
	c, _ := Load()
	out, err := Render(c, []string{"gosec"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "cli.vulnetix.com/install.sh") {
		t.Fatal("the publish job must install the CLI")
	}
	if strings.Contains(out, "--version") {
		t.Error("the CLI install must not pin a version; install.sh resolves the latest release")
	}
	if regexp.MustCompile(`v3\.\d+\.\d+`).MatchString(out) {
		t.Error("rendered workflow contains a hardcoded CLI version")
	}
}

// A scanner that FOUND something exits non-zero — govulncheck 3, terrascan 3,
// zizmor 14. Under GitHub's default `bash -e` the step dies on that line, the
// recipe's "is this valid SARIF" guard never runs, and an empty report is
// uploaded for the publish job to reject. A green scan then reads as a red
// workflow, which is the most expensive kind of wrong.
func TestRenderScannerStepsDoNotAbortOnFirstFailure(t *testing.T) {
	c, _ := Load()
	out, err := Render(c, []string{"govulncheck"}, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out, "shell: bash --noprofile --norc {0}") {
		t.Error("a scanner run step must opt out of `bash -e`, or its report guard never runs")
	}

	// The publish step is the opposite case: if publishing fails, the workflow
	// has to fail with it.
	publish := out[strings.Index(out, "  publish:"):]
	if strings.Contains(publish, "--noprofile") {
		t.Error("the publish job must keep the failing default shell")
	}
}

func TestRenderShape(t *testing.T) {
	c, _ := Load()
	out, err := Render(c, []string{"zizmor", "gosec"}, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// needs must list every scanner, or a job's artifacts are published before
	// it has produced them.
	if !strings.Contains(out, "needs: [gosec, zizmor]") {
		t.Error("publish must depend on every scanner job, sorted")
	}
	// always(), or one failed scanner suppresses everyone else's results.
	if !strings.Contains(out, "if: always()") {
		t.Error("publish must run even when a scanner fails")
	}
	// actions: read is what lets the CLI list the run's artifacts.
	if !strings.Contains(out, "actions: read") {
		t.Error("publish needs actions: read to list artifacts")
	}
	if !strings.Contains(out, "vulnetix gha upload") {
		t.Error("publish must call gha upload")
	}
	if !IsManaged(out) {
		t.Error("output must carry the managed marker so it is not mistaken for hand-written")
	}
}

func TestRenderRejectsUnknownTool(t *testing.T) {
	c, _ := Load()
	if _, err := Render(c, []string{"not-a-tool"}, Options{}); err == nil {
		t.Error("expected an error for an unknown tool")
	}
}

func TestRenderSelfHostedLabels(t *testing.T) {
	c, _ := Load()
	out, _ := Render(c, []string{"gosec"}, Options{SelfHostedLabels: []string{"self-hosted", "Linux", "X64"}})
	if !strings.Contains(out, "runs-on: [self-hosted, Linux, X64]") {
		t.Error("runs-on labels were not applied")
	}
	if strings.Contains(out, "ubuntu-latest") {
		t.Error("ubuntu-latest should have been replaced everywhere, including publish")
	}
}

func TestToolsInWorkflowRoundTrips(t *testing.T) {
	c, _ := Load()
	out, _ := Render(c, []string{"gosec", "kics"}, Options{})
	got := ToolsInWorkflow(c, out)
	if len(got) != 2 || got[0] != "gosec" || got[1] != "kics" {
		t.Errorf("detected %v, want [gosec kics]; setup would drop tools on the next run", got)
	}
}

func TestParseRemote(t *testing.T) {
	cases := []struct {
		url      string
		host     string
		slug     string
		isGitHub bool
	}{
		{"git@github.com:Vulnetix/cli.git", "github.com", "Vulnetix/cli", true},
		{"https://github.com/Vulnetix/cli.git", "github.com", "Vulnetix/cli", true},
		{"ssh://git@github.com/Vulnetix/cli.git", "github.com", "Vulnetix/cli", true},
		{"https://github.acme.com/team/repo.git", "github.acme.com", "team/repo", true},
		{"git@gitlab.com:acme/thing.git", "gitlab.com", "acme/thing", false},
		{"https://bitbucket.org/acme/thing.git", "bitbucket.org", "acme/thing", false},
		// Credentials in the URL must not be mistaken for the host.
		{"https://user:token@github.com/acme/thing.git", "github.com", "acme/thing", true},
	}
	for _, c := range cases {
		got := parseRemote(c.url)
		if got.Host != c.host || got.Slug != c.slug || got.IsGitHub != c.isGitHub {
			t.Errorf("%s -> host=%q slug=%q github=%v, want %q/%q/%v",
				c.url, got.Host, got.Slug, got.IsGitHub, c.host, c.slug, c.isGitHub)
		}
	}
}

// ScanCode emits explicit nulls for the fields it found nothing for, and
// CycloneDX 1.3 types them as strings — so the document is cleaned before
// upload. `version` is the exception to "drop the nulls": the schema lists it
// as REQUIRED on a component, so dropping a null one trades a type error for
// "missing property 'version'" and the upload still fails. It did, in
// production, on every ScanCode run.
func TestScanCodeCleanupBackfillsTheRequiredVersion(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	tool, ok := c.Find("scancode")
	if !ok {
		t.Fatal("catalog is missing scancode")
	}

	var recipe string
	for _, s := range tool.Steps {
		recipe += s.Run
	}
	if !strings.Contains(recipe, "with_entries(select(.value != null))") {
		t.Error("scancode no longer strips null fields; CycloneDX 1.3 rejects them")
	}
	if !strings.Contains(recipe, `.components |= map(.version //= "")`) {
		t.Error("scancode strips nulls without backfilling the required component version; " +
			"every upload will fail on \"missing property 'version'\"")
	}
	if !strings.Contains(recipe, `.metadata.component.version //= ""`) {
		t.Error("scancode does not backfill the metadata component's version")
	}
}

// No recipe may invoke a system Python. uv carries its own interpreter, so a
// converter that runs under it behaves the same on every runner image, cannot
// be broken by a Python that is missing or externally managed, and cannot
// install anything into one. The self-hosted pool's image is exactly that case:
// python3 with no pip, and no actions/setup-python build for the OS.
func TestNoRecipeInvokesSystemPython(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	for _, tool := range c.Tools {
		for _, s := range tool.Steps {
			if s.Run == "" {
				continue
			}
			for i, line := range strings.Split(s.Run, "\n") {
				code, _, _ := strings.Cut(line, "#")
				code = strings.TrimSpace(code)
				if code == "" {
					continue
				}
				for _, bad := range []string{"python3 ", "python ", "pip ", "pip3 "} {
					// A bare invocation at the start of a command, or after a
					// pipe or a command substitution.
					if strings.HasPrefix(code, bad) ||
						strings.Contains(code, "| "+bad) ||
						strings.Contains(code, "$("+bad) {
						t.Errorf("%s line %d invokes a system interpreter: %q\n"+
							"use `uv run --no-project --python 3.12 python -` or `uvx <tool>`", tool.ID, i+1, code)
					}
				}
			}
		}
	}
}

// A repository that has not been given the Vulnetix secrets yet is not broken;
// it simply has nowhere to publish. Failing the publish job over it gives that
// repository a permanent red X reading "authentication required", which names
// no secret and tells nobody what to do about it.
func TestPublishSkipsWithoutCredentials(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(c, []string{"gosec"}, Options{})
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out, `if [ -z "${VULNETIX_ORG_ID:-}" ] || [ -z "${VULNETIX_API_KEY:-}" ]; then`) {
		t.Error("publish job does not guard on the credentials being present")
	}
	if !strings.Contains(out, "::warning::VULNETIX_ORG_ID and VULNETIX_API_KEY are not set") {
		t.Error("the skip does not name the secrets that need setting")
	}
	// exit 0, not exit 1: a missing optional credential is not a build failure.
	guard := out[strings.Index(out, "Publish scanner reports"):]
	if !strings.Contains(guard[:strings.Index(guard, "vulnetix gha upload")], "exit 0") {
		t.Error("the credential guard fails the job instead of skipping it")
	}
}

// No recipe may assume it can become root. The AWS runner pools grant exactly
// one sudo rule — writing the busy/idle heartbeat — because general NOPASSWD
// sudo would hand the instance role to every workflow on the box through IMDS.
// A blind `sudo` there does not fail with "permission denied"; it blocks on a
// password prompt and dies with "sudo: a terminal is required to read the
// password", taking the job with it.
func TestNoRecipeAssumesSudo(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range c.Tools {
		for _, s := range tool.Steps {
			if s.Run == "" {
				continue
			}
			for i, line := range strings.Split(s.Run, "\n") {
				code := strings.TrimSpace(line)
				if code == "" || strings.HasPrefix(code, "#") {
					continue
				}
				if strings.HasPrefix(code, "sudo ") || strings.Contains(code, "| sudo ") {
					t.Errorf("%s line %d runs sudo unconditionally: %q\n"+
						"resolve it first (`sudo -n true`) and degrade to a warning when it is unavailable",
						tool.ID, i+1, code)
				}
			}
		}
	}
}

// A job with no timeout holds a runner until GitHub's six-hour ceiling. That is
// not hypothetical: four jobs on the self-hosted pool hit exactly 360.1 minutes
// before being killed, each having occupied one of twenty-four slots the whole
// time.
func TestEveryJobCarriesATimeout(t *testing.T) {
	c, _ := Load()
	out, err := Render(c, c.IDs(), Options{})
	if err != nil {
		t.Fatal(err)
	}

	var job string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "  ") && strings.HasSuffix(line, ":") &&
			!strings.HasPrefix(line, "   "):
			job = strings.TrimSuffix(strings.TrimSpace(line), ":")
		case strings.HasPrefix(line, "    timeout-minutes:"):
			seen[job] = true
		}
	}

	for _, id := range append(c.IDs(), "publish") {
		if !seen[id] {
			t.Errorf("job %q has no timeout-minutes; a hang there costs six hours of a runner", id)
		}
	}
}

// The tail of slow jobs is three PHP tools. Two of them only ever ran long
// because they hung, so they are capped just above the fleet-wide p99 of 29
// minutes. Dependency-Check is the exception: one legitimate run took 313
// minutes building the NVD database from cold, so its cap has to clear that,
// and the cache is what makes the number shrinkable later.
func TestSlowToolTimeouts(t *testing.T) {
	c, _ := Load()
	want := map[string]int{
		"psalm":                  30,
		"cyclonedx-php":          30,
		"owasp-dependency-check": 330,
	}
	for id, minutes := range want {
		tool, ok := c.Find(id)
		if !ok {
			t.Fatalf("catalog is missing %q", id)
		}
		if tool.TimeoutMinutes != minutes {
			t.Errorf("%s timeout is %d, want %d", id, tool.TimeoutMinutes, minutes)
		}
	}

	dc, _ := c.Find("owasp-dependency-check")
	// Below GitHub's own ceiling on purpose: a hang should be reported as our
	// timeout and give the runner back, not be killed at 360 minutes.
	if dc.TimeoutMinutes >= 360 {
		t.Error("dependency-check timeout must sit below GitHub's 6h job ceiling")
	}
	// And above the one legitimate long run, or the fix breaks real work.
	if dc.TimeoutMinutes <= 313 {
		t.Error("dependency-check timeout must clear the measured 313-minute cold-NVD run")
	}

	out, err := Render(c, []string{"owasp-dependency-check"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "timeout-minutes: 330") {
		t.Error("the per-tool timeout did not reach the rendered job")
	}
	if !strings.Contains(out, "actions/cache@v4") || !strings.Contains(out, "restore-keys:") {
		t.Error("dependency-check must restore the NVD database, or every run rebuilds it from cold")
	}
	if !strings.Contains(out, "--data") {
		t.Error("dependency-check must be pointed at the cached data directory")
	}
}

// The schedule is derived, not random: the workflow is rewritten in full on
// every `gha setup`, so anything clock- or random-derived would produce a diff
// each time and silently move the fleet around.
func TestScheduleCronForIsStableAndStaggered(t *testing.T) {
	if a, b := ScheduleCronFor("vulnetix/cli"), ScheduleCronFor("vulnetix/cli"); a != b {
		t.Errorf("same slug gave %q then %q; regeneration would churn the schedule", a, b)
	}
	if ScheduleCronFor("") != DefaultScheduleCron {
		t.Error("a repository with no slug should fall back to the default schedule")
	}

	// The fleet as it stands. Every repository must land in its own 20-minute
	// slot, which is comfortably longer than the ~7 minutes a full 24-job
	// backlog takes to drain.
	slugs := []string{
		"vulnetix/cli", "vulnetix/vdb-api", "vulnetix/vdb-site", "vulnetix/website",
		"vulnetix/saas", "vulnetix/ai-firewall", "vulnetix/package-firewall",
		"vulnetix/malscan-engine", "vulnetix/mcp-server", "vulnetix/pkgregistry",
		"vulnetix/sast-rule-evals", "vulnetix/sca-manifest-fixtures",
		"vulnetix/vulnetix-fixture-app",
	}
	taken := map[string]string{}
	for _, s := range slugs {
		cron := ScheduleCronFor(s)
		var minute, hour, weekday int
		if _, err := fmt.Sscanf(cron, "%d %d * * %d", &minute, &hour, &weekday); err != nil {
			t.Fatalf("%s produced an unparseable cron %q", s, cron)
		}
		switch {
		case minute < 0 || minute > 59:
			t.Errorf("%s: minute %d out of range", s, minute)
		case hour < 0 || hour > 23:
			t.Errorf("%s: hour %d out of range", s, hour)
		case weekday < 0 || weekday > 6:
			t.Errorf("%s: weekday %d out of range", s, weekday)
		}
		// Never on the hour: GitHub queues every cron on the platform there and
		// delivers them late.
		if minute%60 == 0 {
			t.Errorf("%s: scheduled on the hour (%q)", s, cron)
		}
		if prev, dup := taken[cron]; dup {
			t.Errorf("%s and %s share the slot %q", s, prev, cron)
		}
		taken[cron] = s
	}
}

// Rendering must actually use the derived schedule, and an explicit --cron must
// still win.
func TestRenderSchedulePerRepository(t *testing.T) {
	c, _ := Load()

	a, _ := Render(c, []string{"gosec"}, Options{Triggers: []string{"schedule"}, RepoSlug: "vulnetix/cli"})
	b, _ := Render(c, []string{"gosec"}, Options{Triggers: []string{"schedule"}, RepoSlug: "vulnetix/website"})
	if a == b {
		t.Error("two repositories were given the same schedule; the fleet would pile onto the pool at once")
	}
	if !strings.Contains(a, "cron: '"+ScheduleCronFor("vulnetix/cli")+"'") {
		t.Error("rendered schedule does not match the slug-derived one")
	}

	pinned, _ := Render(c, []string{"gosec"}, Options{
		Triggers:     []string{"schedule"},
		ScheduleCron: "13 5 * * 1",
		RepoSlug:     "vulnetix/cli",
	})
	if !strings.Contains(pinned, "cron: '13 5 * * 1'") {
		t.Error("an explicit --cron must override the derived schedule")
	}
}
