package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// ─────────────────────────────────────────────────────────────────────────
// license_policy_ownership_test.go — the capability-owner lock for licence
// governance.
//
// AGENTS.md names this stage as the cautionary tale: the license stage once
// grew a weaker fixed-policy fork inside cmd/scan.go, so `scan
// --evaluate-licenses` and `license` disagreed about the same repository.
// Policy and exception loading is the same shape of risk — os.ReadFile on a
// YAML file is easy to reach for — so it is locked to one loader.
// ─────────────────────────────────────────────────────────────────────────

// TestPolicyLoadingHasOneOwner asserts that policy and exception documents are
// read only through the loaders in license_policy.go.
func TestPolicyLoadingHasOneOwner(t *testing.T) {
	owner := "license_policy.go"
	forbidden := []string{"license.LoadPolicy(", "license.LoadExceptions("}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if name == owner || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, call := range forbidden {
			if strings.Contains(string(data), call) {
				t.Errorf("%s calls %s directly. Policy loading is owned by %s and reached "+
					"through loadLicenseGovernance; a second loader is how `scan "+
					"--evaluate-licenses` and `license` come to disagree about the same repo.",
					name, call, owner)
			}
		}
	}
}

// TestEvaluationIsReachedThroughThePipeline asserts license.Evaluate has one
// call site: the pipeline entry point.
func TestEvaluationIsReachedThroughThePipeline(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var callers []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "license.Evaluate(") {
			callers = append(callers, name)
		}
	}
	if len(callers) != 1 || callers[0] != "license.go" {
		t.Errorf("license.Evaluate is called from %v; it must be reached only from "+
			"runLicensePipeline in license.go, which is what makes `scan` and `license` "+
			"apply the same policy", callers)
	}
}

// TestLicenseGovernanceFlagsAreFamilyWide pins that --policy-file and
// --exceptions-file exist on `license` and on every scan-family member.
func TestLicenseGovernanceFlagsAreFamilyWide(t *testing.T) {
	commands := map[string]*cobra.Command{
		"license":    licenseCmd,
		"scan":       scanCmd,
		"sca":        scaCmd,
		"sast":       sastCmd,
		"secrets":    secretsCmd,
		"containers": containersCmd,
		"iac":        iacCmd,
	}
	for name, c := range commands {
		for _, flag := range []string{"policy-file", "exceptions-file"} {
			if c.Flags().Lookup(flag) == nil {
				t.Errorf("--%s is not registered on %s; `scan --evaluate-licenses` and "+
					"`license` can only agree if both can be pointed at the same policy",
					flag, name)
			}
		}
	}
}

// TestLicenseSubcommandsRegistered pins the subcommand set.
func TestLicenseSubcommandsRegistered(t *testing.T) {
	want := map[string]map[string]bool{
		"policy":     {"init": false, "show": false, "validate": false},
		"exceptions": {"ls": false, "check": false, "add": false},
	}
	for _, parent := range licenseCmd.Commands() {
		subs, tracked := want[parent.Name()]
		if !tracked {
			continue
		}
		for _, sub := range parent.Commands() {
			if _, expected := subs[sub.Name()]; !expected {
				t.Errorf("unexpected `license %s %s`; add it to this test and to the docs",
					parent.Name(), sub.Name())
				continue
			}
			subs[sub.Name()] = true
		}
	}
	for parent, subs := range want {
		for sub, seen := range subs {
			if !seen {
				t.Errorf("`license %s %s` is not registered", parent, sub)
			}
		}
	}
}

func TestParseDayDuration(t *testing.T) {
	ok := map[string]float64{
		"":     30 * 24, // default
		"30d":  30 * 24,
		"90d":  90 * 24,
		"0d":   0,
		"48h":  48,
		" 7d ": 7 * 24,
	}
	for in, wantHours := range ok {
		got, err := parseDayDuration(in)
		if err != nil {
			t.Errorf("parseDayDuration(%q): %v", in, err)
			continue
		}
		if got.Hours() != wantHours {
			t.Errorf("parseDayDuration(%q) = %v, want %vh", in, got, wantHours)
		}
	}
	for _, bad := range []string{"soon", "-5d", "30days", "d"} {
		if _, err := parseDayDuration(bad); err == nil {
			t.Errorf("parseDayDuration(%q) = nil error, want a failure", bad)
		}
	}
}
