package report

import (
	"fmt"
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
	for _, want := range []string{"4 findings in 2 files", "2 need action", "2 can wait", "VNX-1117", "2 in 1 file"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Worst rule first: the critical secret outranks the high finding.
	if strings.Index(out, "config/prod.env") > strings.Index(out, "src/app.py") {
		t.Errorf("rules should be ordered worst first:\n%s", out)
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

// codeRepeatFixture is one rule firing many times across files, plus the same
// severity in test code and in a vendored tree: the shape of a real repository.
func codeRepeatFixture() CodeReport {
	r := CodeReport{Label: "SAST", RulesLoaded: 774, RulesTotal: 2865}
	add := func(id, sev, path string, line int, test bool) {
		r.Findings = append(r.Findings, CodeFinding{RuleID: id, Name: "Lock() without a deferred Unlock()", Severity: sev, Kind: "sast",
			Path: path, Line: line, Message: "Mutex Lock() not immediately followed by defer Unlock(); add defer", Snippet: "\ts.mu.Lock()", TestSuite: test})
	}
	for _, l := range []int{172, 184, 251, 268, 287, 322, 351, 378, 518, 601} {
		add("VNX-GO-014", "high", "internal/lsp/server.go", l, false)
	}
	for _, l := range []int{231, 247, 252} {
		add("VNX-GO-014", "high", "internal/lsp/sca.go", l, false)
	}
	add("VNX-GO-014", "high", "internal/display/progress.go", 68, false)
	add("VNX-GO-014", "high", "cmd/root.go", 66, false)
	add("VNX-GO-014", "high", "cmd/root_test.go", 12, true)
	add("VNX-GO-014", "high", "cmd/other_test.go", 9, true)
	r.Findings = append(r.Findings,
		CodeFinding{RuleID: "VNX-CRYPTO-004", Name: "Broken or obsolete cipher", Severity: "high", Path: "schemas/third_party/defs.json", Line: 245, Message: "Broken cipher (3DES)"},
		CodeFinding{RuleID: "VNX-1325", Name: "make() sized from len()", Severity: "medium", Path: "cmd/scan.go", Line: 103, Message: "Go make([]...) allocation detected"},
	)
	return r
}

func TestCodeGroupsByRule(t *testing.T) {
	r := codeRepeatFixture()
	out := RenderCode(r, Options{Command: "sast"}, plainTerm(110, true))
	for _, want := range []string{
		"15 need action", "1 can wait", "2 in tests", "1 vendored",
		"NEEDS ACTION", "15 in 4 files", "internal/lsp/server.go", "+ 1 more file",
		"IN TESTS", "VNX-GO-014 2", "VENDORED", "schemas/third_party/",
		"vulnetix sast --explain VNX-GO-014", "vulnetix sast -v",
		"vulnetix sast --show tests", "vulnetix sast --exclude schemas/third_party/",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// The rule's message is printed once, however many places it fired.
	if n := strings.Count(out, "Lock() without a deferred Unlock()"); n != 1 {
		t.Errorf("rule title printed %d times, want once:\n%s", n, out)
	}
	// --show tests ranks test code with the rest.
	shown := RenderCode(r, Options{Command: "sast", Show: map[string]bool{"tests": true}}, plainTerm(110, true))
	if !strings.Contains(shown, "17 need action") || strings.Contains(shown, "IN TESTS") {
		t.Errorf("--show tests should rank test code:\n%s", shown)
	}
	golden(t, "code_rules_110", out)
	golden(t, "code_rules_50", RenderCode(r, Options{Command: "sast"}, plainTerm(50, true)))
	ex, ok := RenderCodeExplain(r, "VNX-GO-014", Options{Command: "sast"}, plainTerm(110, true))
	if !ok {
		t.Fatal("explain found nothing")
	}
	for _, want := range []string{"WHERE", "IN TESTS", "+ 7 more in this file", "vulnetix sast --explain VNX-GO-014 -v"} {
		if !strings.Contains(ex, want) {
			t.Errorf("explain missing %q in:\n%s", want, ex)
		}
	}
	golden(t, "code_rules_explain", ex)
}

func TestVendoredRoot(t *testing.T) {
	for in, want := range map[string]string{
		"schemas/third_party/x.json":   "schemas/third_party/",
		"vendor/github.com/a/b.go":     "vendor/",
		"web/node_modules/lodash/a.js": "web/node_modules/",
		"internal/vendorlike/a.go":     "",
		"third_party":                  "",
	} {
		if got := vendoredRoot(in); got != want {
			t.Errorf("vendoredRoot(%q) = %q, want %q", in, got, want)
		}
	}
}

// A high finding in a vendored test file is vendored: it is someone else's
// code before it is anybody's test.
func TestVendoredWinsOverTests(t *testing.T) {
	f := CodeFinding{RuleID: "X", Severity: "high", Path: "vendor/a/a_test.go", TestSuite: true}
	if g := codeGroupOf(f, Options{}); g != codeVendored {
		t.Errorf("group = %v, want vendored", g)
	}
	f.Path = "a/a_test.go"
	if g := codeGroupOf(f, Options{}); g != codeTests {
		t.Errorf("group = %v, want tests", g)
	}
	if g := codeGroupOf(f, Options{Show: map[string]bool{"tests": true}}); g != codeAction {
		t.Errorf("--show tests: group = %v, want needs action", g)
	}
	f.Severity = "medium"
	if g := codeGroupOf(f, Options{}); g != codeWait {
		t.Errorf("medium in tests: group = %v, want can wait", g)
	}
}

// CAN WAIT lists seven rules by default and every rule at -v.
func TestCanWaitIsCappedUnlessVerbose(t *testing.T) {
	r := CodeReport{Label: "SAST"}
	for i := 0; i < 10; i++ {
		r.Findings = append(r.Findings, CodeFinding{RuleID: fmt.Sprintf("VNX-%02d", i), Severity: "low", Path: "a.go", Line: i + 1, Message: "m"})
	}
	out := RenderCode(r, Options{Command: "sast"}, plainTerm(110, true))
	if !strings.Contains(out, "+ 3 more rules") || strings.Contains(out, "VNX-09") {
		t.Errorf("default view should show seven rules:\n%s", out)
	}
	if v := RenderCode(r, Options{Command: "sast", Verbosity: 1}, plainTerm(110, true)); !strings.Contains(v, "VNX-09") || strings.Contains(v, "more rules") {
		t.Errorf("-v should list every rule:\n%s", v)
	}
}
