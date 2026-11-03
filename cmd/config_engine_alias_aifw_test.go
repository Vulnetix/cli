package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	configschemas "github.com/vulnetix/config-schemas"
)

// aiFirewallPolicyFile writes the first released example of AiFirewallPolicy
// where `ai-firewall apply` looks for it.
func aiFirewallPolicyFile(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	examples := configschemas.Examples("AiFirewallPolicy")
	if len(examples) == 0 {
		t.Fatal("no AiFirewallPolicy example")
	}
	raw, err := configschemas.Example("AiFirewallPolicy", examples[0])
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, ".vulnetix", "ai-firewall.yaml")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAiFirewallApplyDryRunIsAnEnginePlan(t *testing.T) {
	f := newFakeEngine(t)
	aiFirewallPolicyFile(t)
	t.Setenv(configTokenEnv, "vmt_tok")
	cmd := newAiFirewallApplyCommand()
	out, errOut, err := runCmd(t, cmd, "", "--dry-run", "--force")
	if err != nil {
		t.Fatalf("%v\n%s\n%s", err, out, errOut)
	}
	if f.called("POST /config/plan") != 1 || f.called("POST /config/apply") != 0 {
		t.Fatalf("calls %v", f.calls)
	}
	body := f.lastBody("/config/plan")
	if body["manager"] != aiFirewallManager {
		t.Fatalf("manager %v", body["manager"])
	}
	docs, _ := body["documents"].([]any)
	if len(docs) != 1 || docs[0].(map[string]any)["kind"] != "AiFirewallPolicy" {
		t.Fatalf("documents %v", docs)
	}
	if strings.Contains(errOut, "Deprecated") {
		t.Fatalf("the engine path is not deprecated:\n%s", errOut)
	}
}

func TestAiFirewallApplyAppliesThePlanHash(t *testing.T) {
	f := newFakeEngine(t)
	aiFirewallPolicyFile(t)
	t.Setenv(configTokenEnv, "vmt_tok")
	if _, _, err := runCmd(t, newAiFirewallApplyCommand(), "", "--force"); err != nil {
		t.Fatal(err)
	}
	if got := f.lastBody("/config/apply")["planHash"]; got != "hash-1" {
		t.Fatalf("planHash %v", got)
	}
}

func TestAiFirewallApplyRefusedCredentialFallsBack(t *testing.T) {
	f := newFakeEngine(t)
	aiFirewallPolicyFile(t)
	t.Setenv(configTokenEnv, "vmt_tok")
	f.status["/config/plan"] = 403
	f.errBody = map[string]any{"error": "only an owner or admin"}
	cmd := newAiFirewallApplyCommand()
	cmd.SetOut(new(strings.Builder))
	cmd.SetContext(context.Background())
	handled, reason, err := aiFirewallApplyViaEngine(cmd)
	if handled || err != nil || !strings.Contains(reason, "refused the credential") {
		t.Fatalf("handled=%v reason=%q err=%v", handled, reason, err)
	}
}

func TestAiFirewallApplyLocalCatalogStaysLegacy(t *testing.T) {
	newFakeEngine(t)
	aiFirewallPolicyFile(t)
	t.Setenv(configTokenEnv, "vmt_tok")
	cmd := newAiFirewallApplyCommand()
	if err := cmd.Flags().Set("catalog", "baseline.json"); err != nil {
		t.Fatal(err)
	}
	if handled, reason, _ := aiFirewallApplyViaEngine(cmd); handled || reason == "" {
		t.Fatalf("handled=%v reason=%q", handled, reason)
	}
}

func TestAiFirewallExportWritesTheEngineExport(t *testing.T) {
	f := newFakeEngine(t)
	t.Chdir(t.TempDir())
	t.Setenv(configTokenEnv, "vmt_tok")
	f.exportOK = "apiVersion: vulnetix.com/v1\nkind: AiFirewallPolicy\nmetadata: {name: default}\nspec: {}\n"
	if _, _, err := runCmd(t, newAiFirewallExportCommand(), "", "--stdout"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.query["/config/export"], "kind=AiFirewallPolicy") {
		t.Fatalf("query %q", f.query["/config/export"])
	}
}

func TestAiFirewallApplyRefusesAnotherOrgWithoutForce(t *testing.T) {
	newFakeEngine(t)
	aiFirewallPolicyFile(t)
	t.Setenv(configTokenEnv, "vmt_tok")
	_, _, err := runCmd(t, newAiFirewallApplyCommand(), "")
	if err == nil || !strings.Contains(err.Error(), "metadata.org") {
		t.Fatalf("err %v", err)
	}
}
