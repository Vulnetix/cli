package license

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeTemp(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAllowListFromFile(t *testing.T) {
	dir := t.TempDir()
	p := writeTemp(t, dir, "allow.yaml", "licenses:\n  - mit\n  - apache-2.0\n  - Not-A-Known-Id\n")
	al, err := LoadAllowListFromFile(p)
	if err != nil {
		t.Fatal(err)
	}
	// Known ids are normalised to their SPDX spelling; unknown ones are kept.
	if want := []string{"MIT", "Apache-2.0", "Not-A-Known-Id"}; !reflect.DeepEqual(al.Licenses, want) {
		t.Errorf("licenses = %v, want %v", al.Licenses, want)
	}

	if _, err := LoadAllowListFromFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("a missing file is an error")
	}
	bad := writeTemp(t, dir, "bad.yaml", "licenses: [unclosed\n")
	if _, err := LoadAllowListFromFile(bad); err == nil {
		t.Error("invalid YAML is an error")
	}
}

func TestParseAllowListCSV(t *testing.T) {
	al := ParseAllowListCSV(" mit, ,Apache-2.0,,bsd-3-clause ")
	if want := []string{"MIT", "Apache-2.0", "BSD-3-Clause"}; !reflect.DeepEqual(al.Licenses, want) {
		t.Errorf("licenses = %v, want %v", al.Licenses, want)
	}
	if empty := ParseAllowListCSV(""); empty.IsActive() || empty.Licenses != nil {
		t.Errorf("an empty list = %+v", empty)
	}
}

func TestAllowListContainsAndIsActive(t *testing.T) {
	var none *AllowList
	if !none.Contains("GPL-3.0-only") || none.IsActive() {
		t.Error("no allow list allows everything and is not active")
	}
	if empty := (&AllowList{}); !empty.Contains("GPL-3.0-only") || empty.IsActive() {
		t.Error("an empty allow list allows everything and is not active")
	}

	al := ParseAllowListCSV("MIT,Apache-2.0")
	if !al.IsActive() {
		t.Error("a list with entries is active")
	}
	for id, want := range map[string]bool{"MIT": true, "mit": true, "apache-2.0": true, "GPL-3.0-only": false, "": false} {
		if got := al.Contains(id); got != want {
			t.Errorf("Contains(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestExtractManifestLicenses(t *testing.T) {
	dir := t.TempDir()
	for _, tt := range []struct {
		name string
		file string
		body string
		want map[string]string
	}{
		{"package.json string", "a/package.json", `{"license":"mit"}`, map[string]string{"": "MIT"}},
		{"package.json object", "b/package.json", `{"license":{"type":"Apache-2.0","url":"x"}}`, map[string]string{"": "Apache-2.0"}},
		{"package.json without license", "c/package.json", `{"name":"x"}`, map[string]string{}},
		{"package.json garbage", "d/package.json", `{not json`, nil},
		{"composer.json string", "e/composer.json", `{"license":"MIT"}`, map[string]string{"": "MIT"}},
		{"composer.json array takes the first", "f/composer.json", `{"license":["GPL-2.0-only","MIT"]}`, map[string]string{"": "GPL-2.0-only"}},
		{"composer.json without license", "g/composer.json", `{"name":"x"}`, nil},
		{"Cargo.toml", "h/Cargo.toml", "[package]\nname = \"x\"\nlicense = \"MIT\"\n", map[string]string{"": "MIT"}},
		{"Cargo.toml outside [package]", "i/Cargo.toml", "[dependencies]\nlicense = \"MIT\"\n[package]\nname = \"x\"\n", map[string]string{}},
		{"Cargo.toml license-file is not a license", "j/Cargo.toml", "[package]\nlicense-file = \"LICENSE\"\n", map[string]string{}},
		{"pyproject string", "k/pyproject.toml", "[project]\nlicense = 'BSD-3-Clause'\n", map[string]string{"": "BSD-3-Clause"}},
		{"pyproject table", "l/pyproject.toml", "[project]\nlicense = {text = \"MIT\"}\n", map[string]string{"": "MIT"}},
		{"pyproject outside [project]", "m/pyproject.toml", "[tool.x]\nlicense = \"MIT\"\n", map[string]string{}},
		{"other manifest", "n/go.mod", "module x\n", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := writeTemp(t, dir, tt.file, tt.body)
			if got := extractManifestLicenses(p); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractManifestLicenses(%s) = %#v, want %#v", tt.file, got, tt.want)
			}
		})
	}
	if got := extractManifestLicenses(filepath.Join(dir, "nope", "package.json")); got != nil {
		t.Errorf("an unreadable manifest = %v, want nil", got)
	}
}

func TestManifestBasename(t *testing.T) {
	for in, want := range map[string]string{"a/b/package.json": "package.json", "Cargo.toml": "Cargo.toml", "": ""} {
		if got := manifestBasename(in); got != want {
			t.Errorf("manifestBasename(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractLicenseFromDescription(t *testing.T) {
	for desc, want := range map[string]string{
		"This image is licensed under the MIT license.":  "MIT",
		"Released under the Apache License, Version 2.0": "Apache-2.0",
		"apache license 2.0 applies":                     "Apache-2.0",
		"SPDX: Apache-2.0":                               "Apache-2.0",
		"BSD 3-Clause":                                   "BSD-3-Clause",
		"bsd 2-clause license":                           "BSD-2-Clause",
		"Distributed under GPL-2.0":                      "GPL-2.0-only",
		"GPL-3.0 or later":                               "GPL-3.0-only",
		"Mozilla MPL-2.0":                                "MPL-2.0",
		"No licence information here":                    "",
		"":                                               "",
	} {
		if got := extractLicenseFromDescription(desc); got != want {
			t.Errorf("extractLicenseFromDescription(%q) = %q, want %q", desc, got, want)
		}
	}
}
