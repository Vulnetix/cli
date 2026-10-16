package report

import (
	"strings"
	"testing"
)

// A suggested explain command must find what it names: a rule from a pack is
// only evaluated when the pack is loaded, and a finding under an excluded or
// non-default path is only seen with the same inputs.
func TestExplainCommandReproducesTheRun(t *testing.T) {
	o := Options{
		Command: "scan",
		RulePacks: map[string]string{
			"CIGNA-S3-001": "Vulnetix/opa-cigna-tf",
			"AVD-AWS-0086": "Vulnetix/opa-aquasecurity-trivy",
			"VNX-GO-001":   "",
		},
		Replay: map[string][]string{
			"scan": {"--path", "infra", "--exclude", "testdata/**"},
			"iac":  {"--path", "infra", "--exclude", "testdata/**"},
			"sca":  {"--path", "infra"},
		},
	}
	for _, tc := range []struct{ got, want string }{
		{explainCommand(o, codeScanner("iac", o), "CIGNA-S3-001", "cigna-s3-001"),
			"vulnetix iac --rule Vulnetix/opa-cigna-tf --path infra --exclude 'testdata/**' --explain CIGNA-S3-001"},
		// A path query loads every pack that fired there, once each.
		{explainCommand(o, "iac", "main.tf", "AVD-AWS-0086", "CIGNA-S3-001", "AVD-AWS-0086"),
			"vulnetix iac --rule Vulnetix/opa-aquasecurity-trivy --rule Vulnetix/opa-cigna-tf --path infra --exclude 'testdata/**' --explain main.tf"},
		// An embedded rule needs no pack; a scanner with no replay gets no flags.
		{explainCommand(o, codeScanner("sast", o), "VNX-GO-001", "VNX-GO-001"), "vulnetix sast --explain VNX-GO-001"},
		{explainCommand(o, packageScanner(o), "requests"), "vulnetix sca --path infra --explain requests"},
		// Repeating the run loads every pack it loaded.
		{rerunCommand(o, "-v"),
			"vulnetix scan --rule Vulnetix/opa-aquasecurity-trivy --rule Vulnetix/opa-cigna-tf --path infra --exclude 'testdata/**' -v"},
		{strictCommand(Options{Command: "report"}), "vulnetix sca --strict"},
	} {
		if tc.got != tc.want {
			t.Errorf("got  %s\nwant %s", tc.got, tc.want)
		}
	}
}

// The owning scanner, not the one that ran: explaining a dependency through
// `scan` would run every rule as well.
func TestPackageExplainNamesTheScanner(t *testing.T) {
	for cmd, want := range map[string]string{
		"": "sca", "scan": "sca", "sca": "sca", "fix": "sca",
		"containers": "containers", "report": "report", "defend": "defend",
	} {
		if got := packageScanner(Options{Command: cmd}); got != want {
			t.Errorf("%q: got %q, want %q", cmd, got, want)
		}
	}
	out := RenderPackages(fullReport(), Options{Command: "scan"}, plainTerm(110, true))
	if !strings.Contains(out, "vulnetix sca --explain") || strings.Contains(out, "vulnetix scan --explain") {
		t.Errorf("a dependency explain should name sca:\n%s", out)
	}
}

func TestShellQuote(t *testing.T) {
	for in, want := range map[string]string{
		"testdata/**": "'testdata/**'", "a b": "'a b'", "it's": `'it'\''s'`,
		"pkg:npm/@x/y@1.0.0": "pkg:npm/@x/y@1.0.0", "": "''", "--exclude": "--exclude",
	} {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
