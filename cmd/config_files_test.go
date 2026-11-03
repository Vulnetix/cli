package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const detectionRuleDoc = `apiVersion: vulnetix.com/v1
kind: DetectionRule
metadata: {name: brute-force}
spec:
  language: sigma
  file: siem/rules/brute-force.yml
`

// The client reads a DetectionRule's file and sends its text as body; the
// server never sees a path.
func TestConfigPlanSendsDetectionRuleFileAsBody(t *testing.T) {
	f := newFakeEngine(t)
	dir := t.TempDir()
	t.Chdir(dir)
	rule := "title: Brute force\nlogsource: {product: linux}\ndetection: {selection: {a: 1}, condition: selection}\n"
	writeConfigFile(t, filepath.Join(dir, ".vulnetix", "config", "siem", "rules"), "brute-force.yml", rule)
	writeConfigFile(t, filepath.Join(dir, ".vulnetix", "config"), "rule.yaml", detectionRuleDoc)
	if _, _, err := runCmd(t, newConfigPlanCommand(), "", "--manager", "gitops:acme/platform"); err != nil {
		t.Fatal(err)
	}
	docs, _ := f.lastBody("/config/plan")["documents"].([]any)
	if len(docs) != 1 {
		t.Fatalf("documents %v", docs)
	}
	spec := docs[0].(map[string]any)["spec"].(map[string]any)
	if spec["body"] != rule {
		t.Fatalf("body %q", spec["body"])
	}
	if _, ok := spec["file"]; ok {
		t.Fatal("the path must not be sent")
	}
}

func TestInlineConfigFilesRefusesAnEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("no symlinks")
	}
	for _, name := range []string{"../" + filepath.Base(outside) + "/secret.txt", "/etc/hostname", "link/secret.txt"} {
		if _, err := readConfigFile(name, []string{root}); err == nil {
			t.Errorf("%s was read", name)
		}
	}
	if _, err := readConfigFile("missing.txt", []string{root}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("missing: %v", err)
	}
}

func TestInlineConfigFilesNestedFilesAndBothForms(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.md"), []byte("agent"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("beside"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec := map[string]any{"file": "a.md", "files": []any{map[string]any{"path": "x/b.txt", "file": "b.txt"}}}
	d := configDocument{Path: filepath.Join(root, "doc.yaml")}
	d.Kind = "AgentProfile"
	d.Value = map[string]any{"spec": spec}
	if err := inlineConfigFiles([]configDocument{d}, []string{root}); err != nil {
		t.Fatal(err)
	}
	if spec["body"] != "agent" || spec["files"].([]any)[0].(map[string]any)["body"] != "beside" {
		t.Fatalf("%v", spec)
	}
	both := map[string]any{"file": "a.md", "body": "x"}
	d.Value = map[string]any{"spec": both}
	if err := inlineConfigFiles([]configDocument{d}, []string{root}); err == nil {
		t.Fatal("file and body together must fail")
	}
}
