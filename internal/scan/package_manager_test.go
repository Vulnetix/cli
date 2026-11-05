package scan

import "testing"

func detected(rel string) DetectedFile {
	info, ok := DetectManifest(rel)
	if !ok {
		return DetectedFile{RelPath: rel, FileType: FileTypeCycloneDX}
	}
	return DetectedFile{RelPath: rel, FileType: FileTypeManifest, ManifestInfo: info}
}

func TestPackageManagerOf(t *testing.T) {
	present := map[string]bool{
		"yarn.lock": true, "svc/pyproject.toml": true, "svc/uv.lock": true,
		"tool/pyproject.toml": true, "pnpm/pnpm-lock.yaml": true,
	}
	cases := map[string]string{
		"package.json":            "yarn",
		"packages/a/package.json": "yarn", // workspace member, lock at the root
		"pnpm/package.json":       "pnpm",
		"svc/pyproject.toml":      "uv",
		"tool/pyproject.toml":     "pip",
		"go.mod":                  "go",
		"Cargo.lock":              "cargo",
		"requirements.txt":        "pip",
		"Gemfile.lock":            "bundler",
		"pom.xml":                 "maven",
		"build.gradle.kts":        "gradle",
		"composer.lock":           "composer",
		"app/app.csproj":          "nuget",
		"pubspec.lock":            "pub",
		"mix.lock":                "hex",
		"Podfile.lock":            "cocoapods",
		"Package.resolved":        "swift",
		"poetry.lock":             "poetry",
		"Pipfile.lock":            "pipenv",
		"bun.lock":                "bun",
	}
	for rel, want := range cases {
		if got := PackageManagerOf(detected(rel), present); got != want {
			t.Errorf("%s: %q, want %q", rel, got, want)
		}
	}
	if got := PackageManagerOf(DetectedFile{RelPath: "x.cdx.json", FileType: FileTypeCycloneDX}, present); got != "" {
		t.Errorf("a committed SBOM has no manager, got %q", got)
	}
}

// Each file is in one leg: its manager's, or the rest leg when it has none.
func TestManagerLegsPartitionFiles(t *testing.T) {
	files := []DetectedFile{detected("go.mod"), detected("package.json"), detected("yarn.lock"), detected("requirements.txt"),
		detected(".github/workflows/ci.yml"), {RelPath: "repo.cdx.json", FileType: FileTypeCycloneDX}}
	legs := map[string]bool{}
	count := func(s ManagerScope) int {
		kept := s.Filter(files)
		for _, f := range kept {
			if legs[f.RelPath] {
				t.Errorf("%s is in two legs", f.RelPath)
			}
			legs[f.RelPath] = true
		}
		return len(kept)
	}
	yarn, _ := NewManagerScope([]string{"yarn"}, nil)
	goLeg, _ := NewManagerScope([]string{"go"}, nil)
	rest, _ := NewManagerScope(nil, []string{"go", "yarn"})
	total := count(yarn) + count(goLeg) + count(rest)
	if total != len(files) {
		t.Errorf("legs hold %d files of %d", total, len(files))
	}
	if !legs["repo.cdx.json"] || !legs["requirements.txt"] {
		t.Errorf("the rest leg must hold unmanaged files and other managers: %v", legs)
	}
}

func TestManagerScopeRefusals(t *testing.T) {
	if _, err := NewManagerScope([]string{"leftpad"}, nil); err == nil {
		t.Error("an unknown manager must be refused")
	}
	if _, err := NewManagerScope([]string{"npm"}, []string{"yarn"}); err == nil {
		t.Error("--package-manager with --not-package-manager must be refused")
	}
}
