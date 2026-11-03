package platformiac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	gate      = "apiVersion: vulnetix.com/v1\nkind: QualityGate\nmetadata: {name: default}\nspec: {severity: high}\n"
	firewall  = "apiVersion: vulnetix.com/v1\nkind: AiFirewallPolicy\nspec:\n  settings: {logsEnabled: true}\n"
	sarifJSON = `{"version":"2.1.0","runs":[]}`
	cdxJSON   = `{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}`
)

func write(t *testing.T, root string, files map[string]string) {
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

func TestDiscoverRules(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		args    []string
		want    []string // kinds found, in order
		wantErr string
		note    string
	}{
		{name: "non-documents in the folder are skipped",
			files: map[string]string{
				".vulnetix/config/gate.yaml":     gate,
				".vulnetix/config/scan.sarif":    sarifJSON,
				".vulnetix/config/sbom.cdx.json": cdxJSON,
				".vulnetix/config/memory.yaml":   "findings: {}\n",
				".vulnetix/config/notes.txt":     "hello",
			},
			want: []string{"QualityGate"}, note: "sbom.cdx.json"},
		{name: "well-known files are read beside the folder",
			files: map[string]string{
				".vulnetix/config/gate.yaml": gate,
				".vulnetix/ai-firewall.yaml": firewall,
			},
			want: []string{"QualityGate", "AiFirewallPolicy"}},
		{name: "an unknown kind is an error",
			files:   map[string]string{".vulnetix/config/x.yaml": "apiVersion: vulnetix.com/v1\nkind: Nope\n"},
			wantErr: `unknown kind "Nope"`},
		{name: "mixing documents with other content is an error",
			files:   map[string]string{".vulnetix/config/x.yaml": gate + "---\nfoo: bar\n"},
			wantErr: "mixes"},
		{name: "a well-known file holding the wrong kind is an error",
			files:   map[string]string{".vulnetix/ai-firewall.yaml": gate},
			wantErr: "is for AiFirewallPolicy only"},
		{name: "a named file that is not a document is an error",
			files:   map[string]string{"scan.sarif.json": sarifJSON},
			args:    []string{"scan.sarif.json"},
			wantErr: "is not a Platform IaC document"},
		{name: "a broken document is not skipped",
			files:   map[string]string{".vulnetix/config/x.yaml": "apiVersion: vulnetix.com/v1\nkind: [\n"},
			wantErr: "x.yaml"},
		{name: "LicenseExceptions is a local kind",
			files: map[string]string{".vulnetix/license-exceptions.yaml": "apiVersion: vulnetix.com/v1\nkind: LicenseExceptions\nblanket:\n  - license: MPL-2.0\n    reason: ok\n"},
			want:  []string{"LicenseExceptions"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			write(t, root, tc.files)
			var args []string
			for _, a := range tc.args {
				args = append(args, filepath.Join(root, a))
			}
			var notes strings.Builder
			docs, err := Discover(Options{Root: root, Files: args, IncludeWellKnown: true, Notes: &notes})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var kinds []string
			for _, d := range docs {
				kinds = append(kinds, d.Kind)
			}
			if strings.Join(kinds, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("kinds %v, want %v", kinds, tc.want)
			}
			if tc.note != "" && !strings.Contains(notes.String(), tc.note) {
				t.Fatalf("no -v note for %s in %q", tc.note, notes.String())
			}
		})
	}
}

func TestValidatorCoversValidateOnlyKinds(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write(t, root, map[string]string{
		"ok.yaml":     "apiVersion: vulnetix.com/v1\nkind: LicenseExceptions\nmetadata: {name: default}\nspec:\n  packages:\n    - purl: pkg:npm/x\n      reason: vendored\n      expires: 2027-01-31\n",
		"bad.yaml":    "apiVersion: vulnetix.com/v1\nkind: LicenseExceptions\nblanket:\n  - license: GPL-3.0\n",
		"mixed.yaml":  "apiVersion: vulnetix.com/v1\nkind: LicenseExceptions\nmetadata: {name: default}\nspec: {}\nblanket: []\n",
		"gate.yaml":   gate,
		"badgate.yml": "apiVersion: vulnetix.com/v1\nkind: QualityGate\nmetadata: {name: default}\nspec: {severity: urgent}\n",
	})
	for name, valid := range map[string]bool{"ok.yaml": true, "bad.yaml": false, "mixed.yaml": false, "gate.yaml": true, "badgate.yml": false} {
		docs, err := Discover(Options{Root: root, Files: []string{filepath.Join(root, name)}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = v.Validate(docs[0].Document)
		if (err == nil) != valid {
			t.Errorf("%s: valid=%v, err=%v", name, valid, err)
		}
	}
}

func TestLoadSingleton(t *testing.T) {
	root := t.TempDir()
	if d, err := LoadSingleton(root, "AiFirewallPolicy"); err != nil || d != nil {
		t.Fatalf("none: %v %v", d, err)
	}
	write(t, root, map[string]string{".vulnetix/ai-firewall.yaml": firewall})
	d, err := LoadSingleton(root, "AiFirewallPolicy")
	if err != nil || d == nil || !d.WellKnown {
		t.Fatalf("well-known: %+v %v", d, err)
	}
	write(t, root, map[string]string{".vulnetix/config/fw.yaml": firewall})
	if _, err := LoadSingleton(root, "AiFirewallPolicy"); err == nil || !strings.Contains(err.Error(), "defined more than once") {
		t.Fatalf("both places must be an error, got %v", err)
	}
	if err := os.Remove(filepath.Join(root, ".vulnetix", "ai-firewall.yaml")); err != nil {
		t.Fatal(err)
	}
	if d, err := LoadSingleton(root, "AiFirewallPolicy"); err != nil || d == nil || d.WellKnown {
		t.Fatalf("config folder: %+v %v", d, err)
	}
}

func TestNormalizeAndFlatten(t *testing.T) {
	flat := map[string]any{"apiVersion": APIVersion, "kind": "LicensePolicy", "unknown": "warn"}
	n := Normalize(flat).(map[string]any)
	if n["metadata"].(map[string]any)["name"] != "default" || n["spec"].(map[string]any)["unknown"] != "warn" || n["unknown"] != nil {
		t.Fatalf("normalize %+v", n)
	}
	back := Flatten(n).(map[string]any)
	if back["unknown"] != "warn" || back["spec"] != nil || back["kind"] != "LicensePolicy" {
		t.Fatalf("flatten %+v", back)
	}
}

func TestValidatorAcceptsOrganizationDriftProtection(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	write(t, root, map[string]string{
		"ok.yaml":  "apiVersion: vulnetix.com/v1\nkind: Organization\nmetadata: {name: default}\nspec:\n  driftProtection: true\n",
		"bad.yaml": "apiVersion: vulnetix.com/v1\nkind: Organization\nmetadata: {name: default}\nspec:\n  driftProtection: sometimes\n",
	})
	for name, valid := range map[string]bool{"ok.yaml": true, "bad.yaml": false} {
		docs, err := Discover(Options{Root: root, Files: []string{filepath.Join(root, name)}})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := v.Validate(docs[0].Document); (err == nil) != valid {
			t.Errorf("%s: valid=%v err=%v", name, valid, err)
		}
	}
}
