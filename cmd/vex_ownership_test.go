package cmd

import (
	"go/ast"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/internal/vex"
)

// ─────────────────────────────────────────────────────────────────────────
// vex_ownership_test.go — the capability-owner lock for VEX consumption.
//
// The failure this prevents is specific and quiet: a scanner path that reads
// VEX its own way would apply statements with different matching rules from
// `vex apply`, so the same document would suppress a finding in one command and
// not in the other. Nobody would notice until a build failed over a
// vulnerability the vendor had already said does not apply.
// ─────────────────────────────────────────────────────────────────────────

// TestVEXConsumptionHasOneOwner asserts internal/vex is imported only by its
// owner file.
func TestVEXConsumptionHasOneOwner(t *testing.T) {
	const vexPkg = `"github.com/vulnetix/cli/v3/internal/vex"`
	const owner = "vex.go"

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
		if strings.Contains(string(data), vexPkg) {
			t.Errorf("%s imports internal/vex directly. VEX consumption is owned by %s "+
				"and reached through runVEXPass; a second call site is a second set of "+
				"matching rules, so the same document would suppress a finding in one "+
				"command and not in another.", name, owner)
		}
	}
}

// TestVEXPassIsTheEntryPoint asserts the shared function takes one options
// struct, per the capability-owner rule in AGENTS.md.
func TestVEXPassIsTheEntryPoint(t *testing.T) {
	_, f := parseCmdFile(t, "vex.go")

	var found bool
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "runVEXPass" {
			return true
		}
		found = true
		if fn.Type.Params.NumFields() != 1 {
			t.Errorf("runVEXPass takes %d parameters; it must take exactly one options struct",
				fn.Type.Params.NumFields())
			return false
		}
		ident, ok := fn.Type.Params.List[0].Type.(*ast.Ident)
		if !ok || ident.Name != "VEXPassOptions" {
			t.Errorf("runVEXPass parameter is %v, want VEXPassOptions", fn.Type.Params.List[0].Type)
		}
		return false
	})
	if !found {
		t.Fatal("runVEXPass not found in vex.go; it is the entry point AGENTS.md requires")
	}
}

// TestVEXFlagsAreFamilyWide pins that --vex-file and --no-vex are registered on
// every member of the scan family. AGENTS.md: a flag registered family-wide
// must be honoured family-wide.
func TestVEXFlagsAreFamilyWide(t *testing.T) {
	family := map[string]*cobra.Command{
		"scan":       scanCmd,
		"sca":        scaCmd,
		"sast":       sastCmd,
		"secrets":    secretsCmd,
		"containers": containersCmd,
		"iac":        iacCmd,
	}
	for name, c := range family {
		for _, flag := range []string{"vex-file", "no-vex"} {
			if c.Flags().Lookup(flag) == nil {
				t.Errorf("--%s is not registered on %s; a VEX statement must be honoured "+
					"whichever scanner surfaced the finding", flag, name)
			}
		}
	}
}

// TestVEXCommandsRegistered pins the subcommand set.
func TestVEXCommandsRegistered(t *testing.T) {
	want := map[string]bool{"apply": false, "ls": false, "validate": false, "merge": false}
	for _, sub := range vexRootCmd.Commands() {
		name := sub.Name()
		if _, expected := want[name]; !expected {
			t.Errorf("unexpected `vex %s` subcommand; add it to this test and to the docs", name)
			continue
		}
		want[name] = true
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("`vex %s` is not registered", name)
		}
	}
}

// TestVEXSuppressionFiltersGateInput pins the behaviour that makes VEX actually
// change a build's outcome.
//
// The gates read enrichedVulns, not the BOM, so annotating the document is not
// enough — a suppressed finding would still fail the severity gate. Equally, an
// `affected` statement must NOT remove a finding: the publisher said it applies.
func TestVEXSuppressionFiltersGateInput(t *testing.T) {
	pass := &VEXPassResult{Result: &vex.Result{
		Total: 3, Suppressed: 1, Effective: 2,
		Applied: []vex.AppliedStatement{
			{VulnID: "CVE-2020-8203", Status: vex.StatusNotAffected, Suppressed: true},
			{VulnID: "CVE-2024-9999", Status: vex.StatusAffected, Suppressed: false},
		},
	}}

	vulns := []scan.EnrichedVuln{
		{VulnFinding: scan.VulnFinding{CveID: "CVE-2020-8203"}},
		{VulnFinding: scan.VulnFinding{CveID: "CVE-2024-9999"}},
		{VulnFinding: scan.VulnFinding{CveID: "CVE-2099-0000"}},
	}

	got := filterVEXSuppressed(vulns, pass)
	if len(got) != 2 {
		t.Fatalf("gate input has %d findings, want 2", len(got))
	}
	for _, v := range got {
		if v.CveID == "CVE-2020-8203" {
			t.Error("a not_affected finding reached the gates and could still fail a build")
		}
	}
	ids := map[string]bool{}
	for _, v := range got {
		ids[v.CveID] = true
	}
	if !ids["CVE-2024-9999"] {
		t.Error("an `affected` statement removed a finding; the publisher said it applies")
	}
	if !ids["CVE-2099-0000"] {
		t.Error("a finding with no statement was removed")
	}
}

// TestVEXFilterIsIdentityWithoutSuppressions guards the no-VEX path: a scan
// that supplied no documents must see exactly the findings it had.
func TestVEXFilterIsIdentityWithoutSuppressions(t *testing.T) {
	vulns := []scan.EnrichedVuln{{VulnFinding: scan.VulnFinding{CveID: "CVE-1"}}}
	if got := filterVEXSuppressed(vulns, nil); len(got) != 1 {
		t.Errorf("nil pass changed the gate input: %d findings", len(got))
	}
	empty := &VEXPassResult{Result: &vex.Result{Total: 1, Effective: 1}}
	if got := filterVEXSuppressed(vulns, empty); len(got) != 1 {
		t.Errorf("an empty result changed the gate input: %d findings", len(got))
	}
}
