package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanFamily is every command that shares the scan engine. The flags these
// commands advertise must actually work on all of them: --dry-run and
// --list-default-rules were both registered family-wide but implemented only in
// scanCmd.RunE, so `sca --dry-run` ran a live scan and `sast
// --list-default-rules` scanned instead of printing rules.
var scanFamily = []string{"scan", "sca", "sast", "secrets", "containers", "iac"}

func resetScanFamilyFlags(t *testing.T, name string) {
	t.Helper()
	cmd, _, err := rootCmd.Find([]string{name})
	if err != nil {
		t.Fatalf("finding %s: %v", name, err)
	}
	for flag, value := range map[string]string{
		"dry-run":            "false",
		"list-default-rules": "false",
		"path":               ".",
		"no-progress":        "false",
	} {
		if f := cmd.Flags().Lookup(flag); f != nil {
			if err := cmd.Flags().Set(flag, value); err != nil {
				t.Fatalf("resetting %s --%s: %v", name, flag, err)
			}
		}
	}
}

func dryRunFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"package.json":      `{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}`,
		"package-lock.json": `{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}},"node_modules/left-pad":{"version":"1.3.0"}}}`,
		"Dockerfile":        "FROM alpine:3.20\nRUN apk add --no-cache curl\n",
		"main.tf":           "provider \"aws\" {\n  region = \"us-east-1\"\n}\n",
		"app.py":            "import os\npassword = os.environ['PW']\n",
	}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestDryRunHonouredAcrossScanFamily is the regression guard: the flag promises
// "zero API calls", so it must short-circuit before any network work on every
// command that offers it. The test points the API at a closed port — a command
// that reaches the network fails instead of succeeding.
func TestDryRunHonouredAcrossScanFamily(t *testing.T) {
	t.Setenv("VULNETIX_API_URL", "http://127.0.0.1:1")
	root := dryRunFixture(t)

	for _, name := range scanFamily {
		t.Run(name, func(t *testing.T) {
			resetScanFamilyFlags(t, name)
			out, err := executeCommand(t, rootCmd, name,
				"--dry-run", "--path", root,
				"--no-analytics", "--no-banner", "--no-progress",
			)
			if err != nil {
				t.Fatalf("%s --dry-run: %v\n%s", name, err, out)
			}
			if !strings.Contains(out, "[DRY RUN]") {
				t.Errorf("%s --dry-run produced no dry-run banner:\n%s", name, out)
			}
			// The scope line names the passes this command would run, which is how
			// a scoped dry run differs from the generic one.
			if !strings.Contains(out, "Passes:") {
				t.Errorf("%s --dry-run did not report its pass scope:\n%s", name, out)
			}
		})
	}
}

// TestDryRunScopeMatchesCommand checks the report is per-command rather than a
// copy of the generic scan plan.
func TestDryRunScopeMatchesCommand(t *testing.T) {
	t.Setenv("VULNETIX_API_URL", "http://127.0.0.1:1")
	root := dryRunFixture(t)

	cases := map[string]struct {
		wantPasses string
		wantKinds  string
	}{
		"secrets": {wantPasses: "Passes: secrets", wantKinds: "Rule kinds: secrets"},
		"iac":     {wantPasses: "Passes: iac", wantKinds: "Rule kinds: iac"},
		"sca":     {wantPasses: "Passes: sca"},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			resetScanFamilyFlags(t, name)
			out, err := executeCommand(t, rootCmd, name,
				"--dry-run", "--path", root,
				"--no-analytics", "--no-banner", "--no-progress",
			)
			if err != nil {
				t.Fatalf("%s --dry-run: %v", name, err)
			}
			if !strings.Contains(out, want.wantPasses) {
				t.Errorf("%s: missing %q in:\n%s", name, want.wantPasses, out)
			}
			if want.wantKinds != "" && !strings.Contains(out, want.wantKinds) {
				t.Errorf("%s: missing %q in:\n%s", name, want.wantKinds, out)
			}
			// sca parses no rego rules, so it must not claim a rule plan.
			if name == "sca" && strings.Contains(out, "Rule kinds:") {
				t.Errorf("sca dry run must not report rule kinds:\n%s", out)
			}
		})
	}
}

// TestListDefaultRulesHonouredWhereRegistered covers the second silently-ignored
// flag: every command that registers --list-default-rules must print the table
// and exit rather than scanning.
func TestListDefaultRulesHonouredWhereRegistered(t *testing.T) {
	t.Setenv("VULNETIX_API_URL", "http://127.0.0.1:1")

	for _, name := range scanFamily {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Fatalf("finding %s: %v", name, err)
		}
		if cmd.Flags().Lookup("list-default-rules") == nil {
			continue // sca has no rego rules and does not offer the flag
		}
		t.Run(name, func(t *testing.T) {
			resetScanFamilyFlags(t, name)
			out, err := executeCommand(t, rootCmd, name,
				"--list-default-rules", "--path", t.TempDir(),
				"--no-analytics", "--no-banner", "--no-progress",
			)
			if err != nil {
				t.Fatalf("%s --list-default-rules: %v", name, err)
			}
			if !strings.Contains(out, "built-in rules") {
				t.Errorf("%s --list-default-rules printed no rule table:\n%s", name, out)
			}
			if strings.Contains(out, "[DRY RUN]") || strings.Contains(out, "Parsing manifests") {
				t.Errorf("%s --list-default-rules fell through into a scan:\n%s", name, out)
			}
		})
	}
}

// TestSnippetContextRegisteredForSARIFFamily guards the flag move: it shapes
// SARIF output, so every rego-engine command must be able to set it.
func TestSnippetContextRegisteredForSARIFFamily(t *testing.T) {
	for _, name := range []string{"scan", "sast", "secrets", "containers", "iac"} {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Fatalf("finding %s: %v", name, err)
		}
		if cmd.Flags().Lookup("snippet-context") == nil {
			t.Errorf("%s is missing --snippet-context", name)
		}
	}
	// sca emits no SARIF, so it deliberately does not carry the flag.
	if cmd, _, err := rootCmd.Find([]string{"sca"}); err == nil {
		if cmd.Flags().Lookup("snippet-context") != nil {
			t.Error("sca should not carry --snippet-context (it produces no SARIF)")
		}
	}
}
