package scan

import (
	"testing"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// findPkg returns the first ScopedPackage whose Name matches, or a zero value.
func findPkg(pkgs []ScopedPackage, name string) (ScopedPackage, bool) {
	for _, p := range pkgs {
		if p.Name == name {
			return p, true
		}
	}
	return ScopedPackage{}, false
}

// ── parsePackageJSONScoped ───────────────────────────────────────────────────

func TestParsePackageJSONScoped_VersionSpec(t *testing.T) {
	data := []byte(`{
		"dependencies": {
			"exact":   "1.2.3",
			"caret":   "^1.0.0",
			"tilde":   "~2.0",
			"gte":     ">=3.0.0"
		},
		"devDependencies": {
			"dev-exact": "4.0.0",
			"dev-range": "^4.0.0"
		}
	}`)
	pkgs, err := parsePackageJSONScoped(data, "package.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		wantVersion string
		wantSpec    string
		wantDirect  bool
	}{
		{"exact", "1.2.3", "1.2.3", true},
		{"caret", "1.0.0", "^1.0.0", true},
		{"tilde", "2.0", "~2.0", true},
		{"gte", "3.0.0", ">=3.0.0", true},
		{"dev-exact", "4.0.0", "4.0.0", true},
		{"dev-range", "4.0.0", "^4.0.0", true},
	}
	for _, tt := range tests {
		p, ok := findPkg(pkgs, tt.name)
		if !ok {
			t.Errorf("package %q not found", tt.name)
			continue
		}
		if p.Version != tt.wantVersion {
			t.Errorf("%q: Version = %q, want %q", tt.name, p.Version, tt.wantVersion)
		}
		if p.VersionSpec != tt.wantSpec {
			t.Errorf("%q: VersionSpec = %q, want %q", tt.name, p.VersionSpec, tt.wantSpec)
		}
		if p.IsDirect != tt.wantDirect {
			t.Errorf("%q: IsDirect = %v, want %v", tt.name, p.IsDirect, tt.wantDirect)
		}
	}
}

// ── parseRequirementsTxtScoped ───────────────────────────────────────────────

func TestParseRequirementsTxtScoped_VersionSpec(t *testing.T) {
	data := []byte(`
# comment
requests>=2.28.0
flask==2.3.0
django~=4.2
urllib3!=1.26.0
bare-package
`)
	pkgs, err := parseRequirementsTxtScoped(data, "requirements.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		wantVersion string
		wantSpec    string
		wantDirect  bool
	}{
		{"requests", "2.28.0", ">=2.28.0", true},
		{"flask", "2.3.0", "==2.3.0", true},
		{"django", "4.2", "~=4.2", true},
		{"urllib3", "1.26.0", "!=1.26.0", true},
		{"bare-package", "", "", true},
	}
	for _, tt := range tests {
		p, ok := findPkg(pkgs, tt.name)
		if !ok {
			t.Errorf("package %q not found", tt.name)
			continue
		}
		if p.Version != tt.wantVersion {
			t.Errorf("%q: Version = %q, want %q", tt.name, p.Version, tt.wantVersion)
		}
		if p.VersionSpec != tt.wantSpec {
			t.Errorf("%q: VersionSpec = %q, want %q", tt.name, p.VersionSpec, tt.wantSpec)
		}
		if p.IsDirect != tt.wantDirect {
			t.Errorf("%q: IsDirect = %v, want %v", tt.name, p.IsDirect, tt.wantDirect)
		}
	}
}

// ── parsePyprojectTOMLScoped ─────────────────────────────────────────────────

func TestParsePyprojectTOMLScoped_VersionSpec(t *testing.T) {
	data := []byte(`
[project]
name = "myapp"

dependencies = [
    "requests>=2.28",
    "flask==2.3.0",
    "bare-dep",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
]
`)
	pkgs, err := parsePyprojectTOMLScoped(data, "pyproject.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		wantVersion string
		wantSpec    string
		wantDirect  bool
	}{
		{"requests", "2.28", ">=2.28", true},
		{"flask", "2.3.0", "==2.3.0", true},
		{"bare-dep", "", "", true},
		// optional-dependency groups are not considered production-direct
		{"pytest", "7.0", ">=7.0", false},
	}
	for _, tt := range tests {
		p, ok := findPkg(pkgs, tt.name)
		if !ok {
			t.Errorf("package %q not found", tt.name)
			continue
		}
		if p.Version != tt.wantVersion {
			t.Errorf("%q: Version = %q, want %q", tt.name, p.Version, tt.wantVersion)
		}
		if p.VersionSpec != tt.wantSpec {
			t.Errorf("%q: VersionSpec = %q, want %q", tt.name, p.VersionSpec, tt.wantSpec)
		}
		if p.IsDirect != tt.wantDirect {
			t.Errorf("%q: IsDirect = %v, want %v", tt.name, p.IsDirect, tt.wantDirect)
		}
	}
}

// ── parsePipfileScoped ───────────────────────────────────────────────────────

func TestParsePipfileScoped_VersionSpec(t *testing.T) {
	data := []byte(`
[packages]
requests = ">=2.28.0"
flask = "*"
exact = "2.3.0"
withextras = {version = ">=1.0", extras = ["security"]}

[dev-packages]
pytest = ">=7.0"
`)
	pkgs, err := parsePipfileScoped(data, "Pipfile")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		wantVersion string
		wantSpec    string
		wantDirect  bool
	}{
		{"requests", "2.28.0", ">=2.28.0", true},
		// cleanLocalVersion("*") returns "*" (not stripped); spec preserved as-is
		{"flask", "*", "*", true},
		{"exact", "2.3.0", "2.3.0", true},
		{"withextras", "1.0", ">=1.0", true},
		{"pytest", "7.0", ">=7.0", true},
	}
	for _, tt := range tests {
		p, ok := findPkg(pkgs, tt.name)
		if !ok {
			t.Errorf("package %q not found", tt.name)
			continue
		}
		if p.Version != tt.wantVersion {
			t.Errorf("%q: Version = %q, want %q", tt.name, p.Version, tt.wantVersion)
		}
		if p.VersionSpec != tt.wantSpec {
			t.Errorf("%q: VersionSpec = %q, want %q", tt.name, p.VersionSpec, tt.wantSpec)
		}
		if p.IsDirect != tt.wantDirect {
			t.Errorf("%q: IsDirect = %v, want %v", tt.name, p.IsDirect, tt.wantDirect)
		}
	}
}

// ── parseCargoTomlScoped ─────────────────────────────────────────────────────

func TestParseCargoTomlScoped_VersionSpec(t *testing.T) {
	data := []byte(`
[dependencies]
serde = "^1.0"
tokio = { version = "1.28", features = ["full"] }
exact-dep = "1.5.0"

[dev-dependencies]
pretty_assertions = "^1.3"
`)
	pkgs, err := parseCargoTomlScoped(data, "Cargo.toml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		wantVersion string
		wantSpec    string
		wantDirect  bool
	}{
		{"serde", "1.0", "^1.0", true},
		{"tokio", "1.28", "1.28", true},
		{"exact-dep", "1.5.0", "1.5.0", true},
		{"pretty_assertions", "1.3", "^1.3", true},
	}
	for _, tt := range tests {
		p, ok := findPkg(pkgs, tt.name)
		if !ok {
			t.Errorf("package %q not found", tt.name)
			continue
		}
		if p.Version != tt.wantVersion {
			t.Errorf("%q: Version = %q, want %q", tt.name, p.Version, tt.wantVersion)
		}
		if p.VersionSpec != tt.wantSpec {
			t.Errorf("%q: VersionSpec = %q, want %q", tt.name, p.VersionSpec, tt.wantSpec)
		}
		if p.IsDirect != tt.wantDirect {
			t.Errorf("%q: IsDirect = %v, want %v", tt.name, p.IsDirect, tt.wantDirect)
		}
	}
}

// ── parseGemfileScoped ───────────────────────────────────────────────────────

func TestParseGemfileScoped_VersionSpec(t *testing.T) {
	data := []byte(`
source 'https://rubygems.org'

gem 'rails', '~> 7.0'
gem 'pg', '>= 1.1'
gem 'puma', '5.6.4'
gem 'bootsnap', require: false

group :development, :test do
  gem 'rspec-rails', '~> 6.0'
end
`)
	pkgs, err := parseGemfileScoped(data, "Gemfile")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		wantVersion string
		wantSpec    string
	}{
		// cleanLocalVersion strips "~" from "~> 7.0" → "> 7.0" (space preserved).
		// cleanLocalVersion strips ">=" from ">= 1.1" → " 1.1" (leading space preserved).
		// VersionSpec always holds the raw string from the Gemfile.
		{"rails", "> 7.0", "~> 7.0"},
		{"pg", " 1.1", ">= 1.1"},
		{"puma", "5.6.4", "5.6.4"},
		{"rspec-rails", "> 6.0", "~> 6.0"},
	}
	for _, tt := range tests {
		p, ok := findPkg(pkgs, tt.name)
		if !ok {
			t.Errorf("package %q not found", tt.name)
			continue
		}
		if p.Version != tt.wantVersion {
			t.Errorf("%q: Version = %q, want %q", tt.name, p.Version, tt.wantVersion)
		}
		if p.VersionSpec != tt.wantSpec {
			t.Errorf("%q: VersionSpec = %q, want %q", tt.name, p.VersionSpec, tt.wantSpec)
		}
	}
}

// ── parseComposerJSONScoped ──────────────────────────────────────────────────

func TestParseComposerJSONScoped_VersionSpec(t *testing.T) {
	data := []byte(`{
		"require": {
			"php": ">=8.0",
			"laravel/framework": "^10.0",
			"guzzlehttp/guzzle": "~7.4"
		},
		"require-dev": {
			"phpunit/phpunit": "^10.0",
			"exact/pkg": "1.2.3"
		}
	}`)
	pkgs, err := parseComposerJSONScoped(data, "composer.json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name        string
		wantVersion string
		wantSpec    string
		wantDirect  bool
	}{
		// "php" is skipped
		{"laravel/framework", "10.0", "^10.0", true},
		{"guzzlehttp/guzzle", "7.4", "~7.4", true},
		{"phpunit/phpunit", "10.0", "^10.0", true},
		{"exact/pkg", "1.2.3", "1.2.3", true},
	}
	for _, tt := range tests {
		p, ok := findPkg(pkgs, tt.name)
		if !ok {
			t.Errorf("package %q not found", tt.name)
			continue
		}
		if p.Version != tt.wantVersion {
			t.Errorf("%q: Version = %q, want %q", tt.name, p.Version, tt.wantVersion)
		}
		if p.VersionSpec != tt.wantSpec {
			t.Errorf("%q: VersionSpec = %q, want %q", tt.name, p.VersionSpec, tt.wantSpec)
		}
		if p.IsDirect != tt.wantDirect {
			t.Errorf("%q: IsDirect = %v, want %v", tt.name, p.IsDirect, tt.wantDirect)
		}
	}
}
