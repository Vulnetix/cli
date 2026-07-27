package ghasetup

import (
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
