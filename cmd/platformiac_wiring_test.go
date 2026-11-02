package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The licence policy and exceptions are found in .vulnetix/config as well as
// in their well-known files, and defining one in both is an error.
func TestLicenseGovernanceReadsTheConfigFolder(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".vulnetix/config/licence.yaml":    "apiVersion: vulnetix.com/v1\nkind: LicensePolicy\nmetadata: {name: default}\nspec:\n  unknown: fail\n",
		".vulnetix/config/exceptions.yaml": "apiVersion: vulnetix.com/v1\nkind: LicenseExceptions\nmetadata: {name: default}\nspec:\n  blanket:\n    - license: MPL-2.0\n      reason: reviewed\n      expires: 2099-01-31\n",
		".vulnetix/config/scan.sarif":      `{"version":"2.1.0","runs":[]}`,
	})
	policy, exceptions, err := loadLicenseGovernance(LicenseRunOptions{RootPath: root})
	if err != nil {
		t.Fatal(err)
	}
	if policy == nil || policy.Unknown != "fail" {
		t.Fatalf("policy %+v", policy)
	}
	if exceptions == nil || len(exceptions.Blanket) != 1 || exceptions.Blanket[0].Expires != "2099-01-31" {
		t.Fatalf("exceptions %+v", exceptions)
	}

	writeTree(t, root, map[string]string{".vulnetix/license-policy.yaml": "apiVersion: vulnetix.com/v1\nkind: LicensePolicy\nunknown: warn\n"})
	if _, _, err := loadLicenseGovernance(LicenseRunOptions{RootPath: root}); err == nil || !strings.Contains(err.Error(), "defined more than once") {
		t.Fatalf("both places must be an error, got %v", err)
	}
}

// A licence policy written before documents carried apiVersion and kind
// still loads from its well-known file.
func TestLegacyLicensePolicyFileStillLoads(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{".vulnetix/license-policy.yaml": "unknown: fail\n"})
	policy, _, err := loadLicenseGovernance(LicenseRunOptions{RootPath: root})
	if err != nil || policy == nil || policy.Unknown != "fail" {
		t.Fatalf("%+v %v", policy, err)
	}
}

func TestAiFirewallApplyFindsThePolicyInTheConfigFolder(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		".vulnetix/config/firewall.yaml": "apiVersion: vulnetix.com/v1\nkind: AiFirewallPolicy\nspec:\n  settings: {logsEnabled: true}\n",
	})
	wd, _ := os.Getwd()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()

	c := &cobra.Command{}
	c.Flags().StringP("file", "f", ".vulnetix/ai-firewall.yaml", "")
	pf, err := loadAiFirewallPolicy(c, ".vulnetix/ai-firewall.yaml")
	if err != nil || pf.Spec.Settings == nil || pf.Spec.Settings.LogsEnabled == nil || !*pf.Spec.Settings.LogsEnabled {
		t.Fatalf("%+v %v", pf, err)
	}

	if err := os.RemoveAll(filepath.Join(root, ".vulnetix", "config")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAiFirewallPolicy(c, ".vulnetix/ai-firewall.yaml"); err == nil || !strings.Contains(err.Error(), "no AI Firewall policy") {
		t.Fatalf("want a clear error, got %v", err)
	}
}
