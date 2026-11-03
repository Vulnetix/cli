package cmd

import (
	"strings"
	"testing"
)

func TestPackageFirewallPolicySetGoesThroughTheEngine(t *testing.T) {
	f := newFakeEngine(t)
	t.Setenv(configTokenEnv, "vmt_tok")
	t.Setenv("HOME", t.TempDir())
	_, errOut, err := runCmd(t, newConfigSetPackageFirewallCommand(), "", "--cvss-threshold", "7", "--block-malware", "--cooldown-days", "3", "-o", "json")
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	docs, _ := f.lastBody("/config/plan")["documents"].([]any)
	if len(docs) != 1 {
		t.Fatalf("documents %v", docs)
	}
	d := docs[0].(map[string]any)
	spec := d["spec"].(map[string]any)
	if d["kind"] != "PackageFirewallPolicy" || spec["cooldownDays"] != float64(3) ||
		spec["thresholds"].(map[string]any)["cvss"] != float64(7) || spec["block"].(map[string]any)["malware"] != true {
		t.Fatalf("document %v", d)
	}
	if f.lastBody("/config/plan")["manager"] != qualityGateManager || f.called("POST /config/apply") != 1 {
		t.Fatalf("manager/apply: %v", f.calls)
	}
	if strings.Contains(errOut, "Deprecated") {
		t.Fatalf("the engine path is not deprecated:\n%s", errOut)
	}
}
