package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// storedReportFixture writes the CycloneDX document the scanners persist, with a
// single vulnerability to render.
func storedReportFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".vulnetix"), 0o755); err != nil {
		t.Fatal(err)
	}
	bom := `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.7",
	  "serialNumber": "urn:uuid:5f2b0d2c-0000-4000-8000-00000000000a",
	  "version": 1,
	  "metadata": {
	    "timestamp": "2026-07-30T00:00:00Z",
	    "tools": {"components": [{"type": "application", "name": "vulnetix-sca", "version": "test"}]}
	  },
	  "components": [
	    {"type":"library","bom-ref":"pkg:npm/left-pad@1.3.0","name":"left-pad","version":"1.3.0","purl":"pkg:npm/left-pad@1.3.0",
	     "properties":[{"name":"vulnetix:ecosystem","value":"npm"},{"name":"vulnetix:source-file","value":"package.json"}]}
	  ],
	  "vulnerabilities": [
	    {"bom-ref":"CVE-2099-12345","id":"CVE-2099-12345",
	     "source":{"name":"Vulnetix VDB"},
	     "ratings":[{"score":9.8,"severity":"critical","method":"CVSSv31"}],
	     "affects":[{"ref":"pkg:npm/left-pad@1.3.0"}],
	     "properties":[{"name":"vulnetix:source-file","value":"package.json"}]}
	  ]
	}`
	if err := os.WriteFile(filepath.Join(root, ".vulnetix", "sbom.cdx.json"), []byte(bom), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// noAPICalls points the API at a closed port so any SCA/API round-trip fails the
// test instead of passing quietly.
func noAPICalls(t *testing.T) {
	t.Helper()
	t.Setenv("VULNETIX_API_URL", "http://127.0.0.1:1")
}

// resetFlagSet restores the given command's mutable flags to their defaults.
// Cobra flag values live on the command object, so a test that sets a flag would
// otherwise leave it set for every test that runs after it.
//
// A flag the command does not register fails the test, so a renamed flag cannot
// quietly stop being reset; skipMissing relaxes that for a flag family shared by
// commands that do not all register every member.
func resetFlagSet(t *testing.T, cmd *cobra.Command, defaults map[string]string, skipMissing bool) {
	t.Helper()
	for flag, value := range defaults {
		if cmd.Flags().Lookup(flag) == nil {
			if skipMissing {
				continue
			}
			t.Fatalf("%s has no --%s flag to reset", cmd.Name(), flag)
		}
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("resetting %s --%s: %v", cmd.Name(), flag, err)
		}
	}
}

// reportFlagDefaults are the report command's mutable flags a test can leave set;
// each value is the flag's registered default.
var reportFlagDefaults = map[string]string{
	"path":             ".",
	"fresh-exploits":   "false",
	"fresh-advisories": "false",
	"fresh-vulns":      "false",
}

func resetReportFlags(t *testing.T) {
	t.Helper()
	resetFlagSet(t, reportCmd, reportFlagDefaults, false)
}

// TestReportRendersStoredFindings is the core of the new owner: replaying results
// needs no scan and no network.
func TestReportRendersStoredFindings(t *testing.T) {
	noAPICalls(t)
	resetReportFlags(t)
	root := storedReportFixture(t)

	out, err := executeCommand(t, rootCmd, "report",
		"--path", root, "--no-analytics", "--no-banner", "--no-progress")
	if err != nil {
		t.Fatalf("report: %v\n%s", err, out)
	}
	for _, want := range []string{"CVE-2099-12345", "left-pad"} {
		if !strings.Contains(out, want) {
			t.Errorf("report output missing %q:\n%s", want, out)
		}
	}
}

func TestReportAcceptsPositionalPath(t *testing.T) {
	noAPICalls(t)
	resetReportFlags(t)
	root := storedReportFixture(t)

	out, err := executeCommand(t, rootCmd, "report", root,
		"--no-analytics", "--no-banner", "--no-progress")
	if err != nil {
		t.Fatalf("report <path>: %v\n%s", err, out)
	}
	if !strings.Contains(out, "CVE-2099-12345") {
		t.Errorf("positional path was not honoured:\n%s", out)
	}
}

func TestReportWithoutStoredResultsExplainsItself(t *testing.T) {
	noAPICalls(t)
	resetReportFlags(t)

	_, err := executeCommand(t, rootCmd, "report",
		"--path", t.TempDir(), "--no-analytics", "--no-banner", "--no-progress")
	if err == nil {
		t.Fatal("expected an error when there is nothing stored to report")
	}
	if !strings.Contains(err.Error(), "no scan memory found") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// TestScanFromMemoryDelegatesToReport pins the deprecation contract: the flag
// still works and produces the report, so existing pipelines are not broken by
// moving ownership.
func TestScanFromMemoryDelegatesToReport(t *testing.T) {
	noAPICalls(t)
	resetScanFamilyFlags(t, "scan")
	root := storedReportFixture(t)
	t.Cleanup(func() {
		_ = scanCmd.Flags().Set("from-memory", "false")
	})

	out, err := executeCommand(t, rootCmd, "scan", "--from-memory",
		"--path", root, "--no-analytics", "--no-banner", "--no-progress")
	if err != nil {
		t.Fatalf("scan --from-memory: %v\n%s", err, out)
	}
	if !strings.Contains(out, "CVE-2099-12345") {
		t.Errorf("scan --from-memory did not render the stored report:\n%s", out)
	}
	// The flag must be marked deprecated so users are pointed at the owner.
	if f := scanCmd.Flags().Lookup("from-memory"); f == nil || f.Deprecated == "" {
		t.Error("--from-memory should be marked deprecated in favour of `vulnetix report`")
	}
}

// TestReportIsNotAScanner keeps the ownership boundary visible: `report` must not
// grow discovery/evaluation flags. If one is added deliberately, this test is the
// place to reconsider whether it belongs on a scanner instead.
func TestReportIsNotAScanner(t *testing.T) {
	for _, flag := range []string{
		"evaluate-sca", "no-sast", "severity", "block-malware", "sca-autofix", "dry-run",
	} {
		if reportCmd.Flags().Lookup(flag) != nil {
			t.Errorf("report should not own the scanner flag --%s", flag)
		}
	}
}
