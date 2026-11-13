package ghainit

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOneOrTwoLanguagesGetJobsAndARestStep(t *testing.T) {
	p := DefaultPolicy()
	out := Render(p, &Signals{Languages: []string{"python", "javascript"}, Managers: []string{"uv"}}, Options{})
	for _, want := range []string{
		"uses: Vulnetix/cli/sast/python@v4", "uses: Vulnetix/cli/sast/javascript@v4",
		"not-language: python,javascript", "uses: Vulnetix/cli/sca/uv@v4", "not-package-manager: uv",
		"artifact-name: sca",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Count(out, "not-language:") != 1 {
		t.Error("exactly one leg carries the rest step")
	}
}

func TestThreeLanguagesUseTheHighLevelScanner(t *testing.T) {
	out := Render(DefaultPolicy(), &Signals{Languages: []string{"go", "python", "shell"}}, Options{})
	if !strings.Contains(out, "uses: Vulnetix/cli/sast@v4") || strings.Contains(out, "sast/go") {
		t.Errorf("three languages must use sast:\n%s", out)
	}
}

func TestRestStepForNamedLegs(t *testing.T) {
	p := DefaultPolicy()
	p.SAST = Selection{Names: []string{"typescript"}}
	if out := Render(p, &Signals{}, Options{}); !strings.Contains(out, "not-language: typescript") {
		t.Errorf("named legs keep the rest step:\n%s", out)
	}
	p.NoRest = true
	if out := Render(p, &Signals{}, Options{}); strings.Contains(out, "not-language") {
		t.Errorf("no_rest leaves it out:\n%s", out)
	}
}

func TestPrivateRepositoriesGuardOnBelaiBranches(t *testing.T) {
	p := DefaultPolicy()
	p.Triggers = TriggerBelai
	out := Render(p, &Signals{Languages: []string{"go"}}, Options{})
	if got := strings.Count(out, "startsWith(github.head_ref, 'belai/')"); got != strings.Count(out, "\n    runs-on:") {
		t.Errorf("every job needs the guard, %d of them have it:\n%s", got, out)
	}
	if !strings.Contains(out, "pull_request:") {
		t.Error("belai repositories scan pull requests")
	}
}

func TestPublicPullRequestsStayOffTheSelfHostedPool(t *testing.T) {
	p := DefaultPolicy()
	p.Triggers = TriggerPR
	out := Render(p, &Signals{}, Options{})
	if !strings.Contains(out, `github.event_name == 'pull_request' && fromJSON('["ubuntu-latest"]')`) {
		t.Errorf("runs-on must send pull requests to a hosted runner:\n%s", out)
	}
}

func TestGatesApplyToTheirScanner(t *testing.T) {
	p := DefaultPolicy()
	p.Gates = map[string]string{"sast": "critical", "secrets": "high"}
	out := Render(p, &Signals{Languages: []string{"go"}}, Options{})
	if !strings.Contains(out, "fail-on: critical") || !strings.Contains(out, "fail-on: high") {
		t.Errorf("gates missing:\n%s", out)
	}
	if !strings.Contains(out, "fail-on-findings: true") {
		t.Errorf("a gated step must fail its job:\n%s", out)
	}
}

func TestNormalizeIgnoresNarrowedRefs(t *testing.T) {
	a := "      - uses: Vulnetix/cli/sast/go@v4\n"
	b := "      - uses: Vulnetix/cli/sast/go@v4.24.0 # locked\n"
	if Normalize(a) != Normalize(b) {
		t.Error("a narrowed ref must not read as drift")
	}
}

func TestPublishAndTEAFollowTheLegs(t *testing.T) {
	p := DefaultPolicy()
	out := Render(p, &Signals{Managers: []string{"go"}}, Options{})
	for _, want := range []string{"needs: [secrets, sast, sca-go, sbom]", "Vulnetix/cli/gha-upload@v4", "Vulnetix/cli/tea-release@v4", "needs: [sbom]", "fetch-depth: 0", "continue-on-error: true", "types: [published]"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	p.TEA = &TEA{Off: true}
	if out := Render(p, &Signals{Managers: []string{"go"}}, Options{}); strings.Contains(out, "tea-release") {
		t.Error("tea off must drop the job")
	}
}

// The forge pass spends the repository's shared hourly token quota, so a pull
// request runs analyze without it and the push to the default branch keeps it.
func TestAnalyzeSkipsTheForgeOnPullRequests(t *testing.T) {
	p := DefaultPolicy()
	p.Analyze = true
	out := Render(p, &Signals{}, Options{})
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(out), &wf); err != nil {
		t.Fatalf("rendered workflow is not YAML: %v\n%s", err, out)
	}
	for _, s := range wf.Jobs["analyze"].Steps {
		if !strings.HasPrefix(s.Uses, "Vulnetix/cli/analyze@") {
			continue
		}
		want := "${{ github.event_name == 'pull_request' && '--no-forge' || '' }}"
		if got := s.With["extra-args"]; got != want {
			t.Errorf("analyze extra-args = %q, want %q", got, want)
		}
		return
	}
	t.Errorf("no analyze step:\n%s", out)
}

// A scanner given the job token resolves unknown licences through the GitHub
// API, which spends the repository's shared quota; a pull request withholds it.
func TestScannersGetNoTokenOnPullRequests(t *testing.T) {
	p := DefaultPolicy()
	p.Analyze, p.CBOM, p.AIBOM, p.License = true, true, true, true
	out := Render(p, &Signals{Languages: []string{"go"}, Managers: []string{"go"}}, Options{})
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(out), &wf); err != nil {
		t.Fatalf("rendered workflow is not YAML: %v\n%s", err, out)
	}
	want := "${{ github.event_name != 'pull_request' && github.token || '' }}"
	for _, id := range []string{"sast-go", "sca-go", "license", "cbom", "aibom", "analyze", "sbom"} {
		job, ok := wf.Jobs[id]
		if !ok {
			t.Errorf("no %s job:\n%s", id, out)
			continue
		}
		for _, s := range job.Steps {
			if !strings.HasPrefix(s.Uses, "Vulnetix/cli/") {
				continue
			}
			if got := s.With["github-token"]; got != want {
				t.Errorf("%s %s github-token = %q, want %q", id, s.Uses, got, want)
			}
		}
	}
}

func TestSetupExtraTakesNoInputs(t *testing.T) {
	p := DefaultPolicy()
	p.Extras = []Extra{{Action: "setup", Then: []string{"vulnetix version"}}}
	out := Render(p, &Signals{}, Options{})
	if !strings.Contains(out, "Vulnetix/cli/setup@v4") || strings.Contains(out, "setup@v4\n        with:") || !strings.Contains(out, "- run: vulnetix version") {
		t.Errorf("setup must render bare:\n%s", out)
	}
}

func TestExtrasRenderTheirInputs(t *testing.T) {
	p := DefaultPolicy()
	p.Extras = []Extra{{Action: "bom-validate", Run: []string{"echo hi"}, With: map[string]string{"file": "x.cdx.json"}, Permissions: map[string]string{"issues": "read"}}}
	out := Render(p, &Signals{}, Options{})
	for _, want := range []string{"  bom-validate:\n", "- run: echo hi", "file: x.cdx.json", "issues: read"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
}

func TestPolicyValuesSurviveAsYAML(t *testing.T) {
	for in, want := range map[string]string{
		"python,javascript": "python,javascript", "echo hi": "echo hi", "*.cdx.json": `"*.cdx.json"`,
		"a: b": `"a: b"`, "x # y": `"x # y"`, "[a]": `"[a]"`, "- x": `"- x"`, "null": `"null"`,
		"${{ github.event_name == 'push' }}": "${{ github.event_name == 'push' }}", "true": "true",
	} {
		if got := yamlValue(in); got != want {
			t.Errorf("yamlValue(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestForkBranchNamedBelaiDoesNotGuardIn(t *testing.T) {
	p := DefaultPolicy()
	p.Triggers = TriggerBelai
	out := Render(p, &Signals{Languages: []string{"go"}}, Options{})
	if !strings.Contains(out, "github.event.pull_request.head.repo.full_name == github.repository") {
		t.Errorf("a fork's belai/ branch must not pass the guard:\n%s", out)
	}
}

func TestRestStepRunsAfterAGatedFailure(t *testing.T) {
	p := DefaultPolicy()
	p.Gates = map[string]string{"sast": "critical"}
	out := Render(p, &Signals{Languages: []string{"go"}}, Options{})
	if !strings.Contains(out, "Vulnetix/cli/sast@v4\n        if: ${{ !cancelled() }}") {
		t.Errorf("the rest step must run when the leg's gate fails:\n%s", out)
	}
}

func TestNoDetectedLanguageStillGetsSAST(t *testing.T) {
	out := Render(DefaultPolicy(), &Signals{}, Options{})
	if !strings.Contains(out, "Vulnetix/cli/sast@v4") {
		t.Errorf("source below the threshold is still scanned:\n%s", out)
	}
}

func TestHighLevelSCAAndSBOMDoNotShareAnArtifactName(t *testing.T) {
	out := Render(DefaultPolicy(), &Signals{Managers: []string{"go", "npm", "pip"}}, Options{})
	if strings.Count(out, "artifact-name: sca\n") != 1 || !strings.Contains(out, "artifact-name: sca-scan") {
		t.Errorf("one artifact named sca:\n%s", out)
	}
}

func TestPolicyValidation(t *testing.T) {
	bad := []*Policy{
		{Triggers: "pul"},
		{Triggers: TriggerPush, Runner: "x'] }"},
		{Triggers: TriggerPush, SAST: Selection{Names: []string{"cobol"}}},
		{Triggers: TriggerPush, SCA: Selection{Names: []string{"leftpad"}}},
		{Triggers: TriggerPush, Extras: []Extra{{Action: "sast@evil"}}},
		{Triggers: TriggerPush, Extras: []Extra{{Action: "gha-audit", ID: "x\ny"}}},
	}
	for i, p := range bad {
		if p.Validate() == nil {
			t.Errorf("policy %d should be refused", i)
		}
	}
	if err := (&Policy{Triggers: TriggerPR, Runner: "vulnetix-local", SAST: Selection{Names: []string{"typescript"}}, Extras: []Extra{{Action: "sast/go"}, {Action: "."}}}).Validate(); err != nil {
		t.Errorf("a good policy was refused: %v", err)
	}
}

// The TEA job downloads the BOM artifacts with a brace glob. The value reaches
// the workflow through yamlValue, so a pre-quoted literal ends up with its quotes
// inside the pattern, which matches no artifact: the job then publishes an empty
// collection and, with continue-on-error, still passes.
func TestTEADownloadPatternIsTheBareGlob(t *testing.T) {
	out := Render(DefaultPolicy(), &Signals{Managers: []string{"go"}}, Options{})
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(out), &wf); err != nil {
		t.Fatalf("rendered workflow is not YAML: %v\n%s", err, out)
	}
	found := false
	for _, s := range wf.Jobs["tea"].Steps {
		if !strings.HasPrefix(s.Uses, "actions/download-artifact@") {
			continue
		}
		found = true
		if got := s.With["pattern"]; got != "{sca,cbom,aibom}" {
			t.Errorf("download pattern = %q, want {sca,cbom,aibom}", got)
		}
	}
	if !found {
		t.Errorf("the tea job has no download-artifact step:\n%s", out)
	}
}
