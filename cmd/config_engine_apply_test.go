package cmd

import (
	"bytes"
	configschemas "github.com/vulnetix/config-schemas"
	"gopkg.in/yaml.v3"
	"path/filepath"
	"strings"
	"testing"
)

func applyArgs(t *testing.T) []string {
	return []string{"-f", gateFile(t, ""), "--manager", "gitops:acme/platform", "--token", "t", "--auto-approve"}
}

// A 207 from apply, or an object whose phase is Failed, is a failed step.
func TestConfigApplyPartialFailureExitsNonZero(t *testing.T) {
	for name, tc := range map[string]struct {
		code   int
		failed int
		phase  string
	}{
		"207 with a failed object": {code: 207, failed: 1, phase: "Failed"},
		"207 alone":                {code: 207, phase: "Applied"},
		"a failed phase on a 200":  {phase: "Failed"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakeEngine(t)
			f.applyCode, f.applyFailed = tc.code, tc.failed
			f.applyItems = []any{map[string]any{"kind": "QualityGate", "name": "default", "action": "update",
				"status": map[string]any{"phase": tc.phase, "message": "guardian refused the write"}}}
			out, _, err := runCmd(t, newConfigApplyCommand(), "", applyArgs(t)...)
			if err == nil {
				t.Fatalf("a partial apply must fail:\n%s", out)
			}
			if got := ExitCode(err); got != ExitFailure {
				t.Fatalf("exit %d, want %d (%v)", got, ExitFailure, err)
			}
			if !strings.Contains(err.Error(), "applied only in part") {
				t.Fatalf("error %q", err)
			}
			if tc.phase == "Failed" && !strings.Contains(out, "guardian refused the write") {
				t.Fatalf("the failure reason is not shown:\n%s", out)
			}
		})
	}
}

func TestConfigApplyCleanSuccessStillExitsZero(t *testing.T) {
	f := newFakeEngine(t)
	f.applyItems = []any{map[string]any{"kind": "QualityGate", "name": "default", "action": "update",
		"status": map[string]any{"phase": "Applied"}}}
	if _, _, err := runCmd(t, newConfigApplyCommand(), "", applyArgs(t)...); err != nil {
		t.Fatal(err)
	}
}

func TestConfigPlanForbiddenNamesOwnerOnlyKinds(t *testing.T) {
	f := newFakeEngine(t)
	f.status["/config/plan"] = 403
	f.errBody = map[string]any{"error": "this token's role is admin; plan, apply and export need owner or admin"}
	doc := writeConfigFile(t, t.TempDir(), "org.yaml", "apiVersion: vulnetix.com/v1\nkind: Organization\nmetadata: {name: default}\nspec: {}\n")
	_, _, err := runCmd(t, newConfigPlanCommand(), "", "-f", doc, "--manager", "gitops:acme/platform", "--token", "t")
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "Organization can only be planned and applied with an owner token") {
		t.Fatalf("no owner hint: %v", err)
	}
}

// With no -f, plan reads .vulnetix/config and the well-known files.
func TestConfigPlanIncludesWellKnownFiles(t *testing.T) {
	f := newFakeEngine(t)
	dir := t.TempDir()
	t.Chdir(dir)
	writeConfigFile(t, filepath.Join(dir, ".vulnetix", "config"), "gate.yaml", validGate)
	writeConfigFile(t, filepath.Join(dir, ".vulnetix"), "ai-firewall.yaml", "apiVersion: vulnetix.com/v1\nkind: AiFirewallPolicy\nspec: {}\n")
	lp, err := configschemas.Example("LicensePolicy", configschemas.Examples("LicensePolicy")[0])
	if err != nil {
		t.Fatal(err)
	}
	lpDocs, err := configschemas.Decode(bytes.NewReader(lp))
	if err != nil || len(lpDocs) == 0 {
		t.Fatal(err)
	}
	lpYAML, _ := yaml.Marshal(lpDocs[0].Value)
	writeConfigFile(t, filepath.Join(dir, ".vulnetix"), "license-policy.yaml", string(lpYAML))
	_, errOut, err := runCmd(t, newConfigPlanCommand(), "", "--manager", "gitops:acme/platform", "--token", "t")
	if err != nil {
		t.Fatalf("%v\n%s", err, errOut)
	}
	var kinds []string
	for _, d := range f.lastBody("/config/plan")["documents"].([]any) {
		kinds = append(kinds, d.(map[string]any)["kind"].(string))
	}
	got := strings.Join(kinds, ",")
	if !strings.Contains(got, "QualityGate") || !strings.Contains(got, "AiFirewallPolicy") {
		t.Fatalf("sent %s", got)
	}
	if strings.Contains(got, "LicensePolicy") || !strings.Contains(errOut, "LicensePolicy") {
		t.Fatalf("LicensePolicy is validated here, not sent: sent %s\n%s", got, errOut)
	}
}
