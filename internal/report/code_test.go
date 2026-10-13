package report

import (
	"strings"
	"testing"
)

func codeFixture() CodeReport {
	return CodeReport{Label: "SAST", RulesLoaded: 1427, RulesTotal: 1899, Findings: []CodeFinding{
		{RuleID: "VNX-PY-004", Name: "yaml.load() without SafeLoader", Severity: "high", Kind: "sast", Path: "src/app.py", Line: 5,
			Message: "yaml.load() without SafeLoader; use yaml.safe_load() or pass Loader=SafeLoader", Snippet: "    data = yaml.load(doc)",
			Description: "yaml.load() without an explicit safe Loader can deserialize arbitrary Python objects.", HelpURI: "https://example.invalid/rules/vnx-py-004", CWE: []int{502}},
		{RuleID: "VNX-SEC-001", Severity: "critical", Kind: "secrets", Path: "config/prod.env", Line: 7,
			Message: "AWS access key ID found; rotate the key", Snippet: "AWS_KEY=AKIAIOSFODNN7EXAMPLE"},
		{RuleID: "VNX-1117", Severity: "low", Kind: "sast", Path: "src/app.py", Line: 4, Message: "Function without docstring summary", Snippet: "def run(cmd, doc):"},
		{RuleID: "VNX-1117", Severity: "low", Kind: "sast", Path: "src/app.py", Line: 4, Message: "Function without docstring summary", Snippet: "def run(cmd, doc):"},
	}}
}

func TestGoldenCode(t *testing.T) {
	r := codeFixture()
	golden(t, "code_110", RenderCode(r, Options{Command: "scan"}, plainTerm(110, true)))
	golden(t, "code_50", RenderCode(r, Options{Command: "scan"}, plainTerm(50, true)))
	golden(t, "code_verbose", RenderCode(r, Options{Command: "scan", Verbosity: 1}, plainTerm(110, true)))
	golden(t, "code_plain", RenderCodePlain(r, Options{Command: "scan"}, plainTerm(100, false)))
	golden(t, "code_github", RenderCodeGitHub(r))
	out, ok := RenderCodeExplain(r, "VNX-PY-004", Options{}, plainTerm(100, true))
	if !ok {
		t.Fatal("explain found nothing")
	}
	golden(t, "code_explain", out)
}

// The point of a secrets finding is that the value should not travel. It must
// not appear in the default view, at -v, in plain output, or under --explain.
func TestSecretValuesAreNeverPrinted(t *testing.T) {
	r := codeFixture()
	const secret = "AKIAIOSFODNN7EXAMPLE"
	for name, out := range map[string]string{
		"default": RenderCode(r, Options{}, plainTerm(110, true)),
		"-v":      RenderCode(r, Options{Verbosity: 1}, plainTerm(110, true)),
		"-vv":     RenderCode(r, Options{Verbosity: 2}, plainTerm(110, true)),
		"plain":   RenderCodePlain(r, Options{}, plainTerm(110, false)),
		"github":  RenderCodeGitHub(r),
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%s output printed the secret:\n%s", name, out)
		}
	}
	if out, _ := RenderCodeExplain(r, "VNX-SEC-001", Options{}, plainTerm(100, true)); strings.Contains(out, secret) {
		t.Errorf("--explain printed the secret:\n%s", out)
	}
}

func TestCodeGroupingAndFiltering(t *testing.T) {
	r := codeFixture()
	out := RenderCode(r, Options{}, plainTerm(110, true))
	for _, want := range []string{"4 findings in 2 files", "2 need action", "2 can wait", "×2"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Worst file first: the critical secret outranks the high finding.
	if strings.Index(out, "config/prod.env") > strings.Index(out, "src/app.py") {
		t.Errorf("files should be ordered worst first:\n%s", out)
	}
	if got := RenderCode(r, Options{MinSeverity: "high"}, plainTerm(110, true)); strings.Contains(got, "VNX-1117") {
		t.Errorf("--min-severity high kept a low finding:\n%s", got)
	}
	if got := RenderCode(CodeReport{Label: "SAST", RulesLoaded: 10}, Options{Quiet: true}, plainTerm(100, true)); got != "" {
		t.Errorf("quiet and clean must print nothing, got %q", got)
	}
	if got := RenderCode(CodeReport{Label: "SAST", RulesLoaded: 10}, Options{}, plainTerm(100, true)); !strings.Contains(got, "No sast findings") {
		t.Errorf("a clean run should say so:\n%s", got)
	}
}
