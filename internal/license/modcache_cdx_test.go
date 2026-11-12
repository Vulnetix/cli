package license

import (
	"path/filepath"
	"testing"
)

const mitText = "MIT License\n\nPermission is hereby granted, free of charge, to any person"

func TestGoModCaseEncode(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/Masterminds/semver": "github.com/!masterminds/semver",
		"github.com/BurntSushi/toml":    "github.com/!burnt!sushi/toml",
		"golang.org/x/net":              "golang.org/x/net",
	} {
		if got := goModCaseEncode(in); got != want {
			t.Errorf("goModCaseEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGoModCachePath(t *testing.T) {
	t.Setenv("GOMODCACHE", "/cache/mod")
	t.Setenv("GOPATH", "/gopath")
	if got := goModCachePath(); got != "/cache/mod" {
		t.Errorf("GOMODCACHE wins: %q", got)
	}

	t.Setenv("GOMODCACHE", "")
	if got := goModCachePath(); got != filepath.Join("/gopath", "pkg", "mod") {
		t.Errorf("then GOPATH/pkg/mod: %q", got)
	}

	t.Setenv("GOPATH", "")
	t.Setenv("HOME", "/home/someone")
	if got := goModCachePath(); got != filepath.Join("/home/someone", "go", "pkg", "mod") {
		t.Errorf("then ~/go/pkg/mod: %q", got)
	}

	t.Setenv("HOME", "")
	if got := goModCachePath(); got != "" {
		t.Errorf("no home directory: %q, want \"\"", got)
	}
}

func TestFindLicenseInModuleCache(t *testing.T) {
	cache := t.TempDir()
	t.Setenv("GOMODCACHE", cache)

	// Case-encoded directory, as the go command writes it.
	writeTemp(t, cache, "github.com/!masterminds/semver@v3.2.0/LICENSE.txt", mitText)
	// A layout that kept the original case.
	writeTemp(t, cache, "example.com/Plain@v1.0.0/COPYING", "Apache License\nVersion 2.0, January 2004")
	// A licence file that says nothing classifiable.
	writeTemp(t, cache, "example.com/odd@v0.1.0/LICENSE", "All rights reserved, ask us.")

	for _, tt := range []struct {
		module, version, want string
	}{
		{"github.com/Masterminds/semver", "v3.2.0", "MIT"},
		{"github.com/Masterminds/semver", "3.2.0", "MIT"}, // the v prefix is added
		{"example.com/Plain", "v1.0.0", "Apache-2.0"},     // falls back to the plain path
		{"example.com/odd", "v0.1.0", ""},
		{"example.com/missing", "v1.0.0", ""},
	} {
		if got := FindLicenseInModuleCache(tt.module, tt.version); got != tt.want {
			t.Errorf("FindLicenseInModuleCache(%s, %s) = %q, want %q", tt.module, tt.version, got, tt.want)
		}
	}

	t.Setenv("GOMODCACHE", "")
	t.Setenv("GOPATH", "")
	t.Setenv("HOME", "")
	if got := FindLicenseInModuleCache("github.com/Masterminds/semver", "v3.2.0"); got != "" {
		t.Errorf("no module cache at all: %q", got)
	}
}

func TestFindLicenseInDirTakesTheFirstClassifiableFile(t *testing.T) {
	dir := t.TempDir()
	// LICENSE comes first in priority but cannot be classified; COPYING can.
	writeTemp(t, dir, "LICENSE", "see the COPYING file")
	writeTemp(t, dir, "COPYING", "GNU GENERAL PUBLIC LICENSE\nVersion 3")
	if got := FindLicenseInDir(dir); got != "GPL-3.0-only" {
		t.Errorf("FindLicenseInDir = %q", got)
	}
	if got := FindLicenseInDir(t.TempDir()); got != "" {
		t.Errorf("no licence file = %q", got)
	}
}

func TestFindingsToCDXVulnerabilities(t *testing.T) {
	packages := []PackageLicense{
		{PackageName: "left-pad", PackageVersion: "1.0.0", Ecosystem: "NPM"},
		{PackageName: "left-pad", PackageVersion: "1.0.0", Ecosystem: "other"}, // first wins
	}
	findings := []Finding{
		{
			ID: "LIC-1", Description: "copyleft", Severity: "high", Confidence: 0.9, Category: "copyleft",
			Package: PackageLicense{
				PackageName: "left-pad", PackageVersion: "1.0.0", LicenseSpdxID: "GPL-3.0-only",
				SourceFile: "package.json", IsDirect: true,
			},
			PathCount:       2,
			IntroducedPaths: [][]string{{"app", "left-pad"}, {"app", "lib", "left-pad"}},
			Evidence:        []EvidenceStep{{Rule: "category", Result: "FAIL"}},
		},
		{
			ID: "LIC-2", Severity: "low", Confidence: 0.5, Category: "unknown",
			Package: PackageLicense{PackageName: "not-in-the-bom", PackageVersion: "2.0.0"},
		},
	}

	vulns := FindingsToCDXVulnerabilities(findings, packages)
	if len(vulns) != 2 {
		t.Fatalf("got %d vulnerabilities", len(vulns))
	}

	v := vulns[0]
	if v.ID != "LIC-1" || v.BOMRef != "LIC-1" || v.Source == nil || v.Source.Name != CDXSourceName {
		t.Errorf("identity = %+v", v)
	}
	if len(v.Ratings) != 1 || v.Ratings[0].Score == nil || *v.Ratings[0].Score != 0.9 || v.Ratings[0].Method != "other" || v.Ratings[0].Severity != "high" {
		t.Errorf("ratings = %+v", v.Ratings)
	}
	if len(v.Affects) != 1 || v.Affects[0].Ref != "pkg:npm/left-pad@1.0.0" {
		t.Errorf("affects = %+v", v.Affects)
	}
	props := map[string]string{}
	for _, p := range v.Properties {
		props[p.Name] = p.Value
	}
	for name, want := range map[string]string{
		"vulnetix:license-category":   "copyleft",
		"vulnetix:license-severity":   "high",
		"vulnetix:license-confidence": "0.90",
		"vulnetix:license-spdx-id":    "GPL-3.0-only",
		"vulnetix:source-file":        "package.json",
		"vulnetix:is-direct":          "true",
		"vulnetix:path-count":         "2",
		"vulnetix:introduced-path-0":  "app → left-pad",
		"vulnetix:introduced-path-1":  "app → lib → left-pad",
		"vulnetix:evidence-0:rule":    "category",
		"vulnetix:evidence-0:result":  "FAIL",
	} {
		if props[name] != want {
			t.Errorf("%s = %q, want %q", name, props[name], want)
		}
	}

	w := vulns[1]
	if w.Affects != nil {
		t.Errorf("a package not in the BOM has no affects: %+v", w.Affects)
	}
	wprops := map[string]string{}
	for _, p := range w.Properties {
		wprops[p.Name] = p.Value
	}
	if wprops["vulnetix:is-direct"] != "false" {
		t.Errorf("is-direct = %q", wprops["vulnetix:is-direct"])
	}
	for _, absent := range []string{"vulnetix:license-spdx-id", "vulnetix:source-file", "vulnetix:path-count", "vulnetix:introduced-path-0"} {
		if _, ok := wprops[absent]; ok {
			t.Errorf("%s set without data", absent)
		}
	}

	if got := FindingsToCDXVulnerabilities(nil, nil); got == nil || len(got) != 0 {
		t.Errorf("no findings = %#v, want an empty slice", got)
	}
}
