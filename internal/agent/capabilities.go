package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// CapabilitiesFile is where the detected surface is recorded.
//
// The path, the schema and the key names are a contract with the plugin's
// skills, which read this file to scope themselves to what a machine actually
// has. It is reproduced here rather than redesigned: the point of moving
// detection into Go is that it becomes correct and cross-platform, not that it
// becomes different.
const CapabilitiesFile = ".vulnetix/capabilities.yaml"

// capabilitiesTTL is how long a detection stays fresh.
//
// Detection is cheap but not free — it stats a few dozen paths and resolves a
// few dozen binaries — and the answer changes about as often as someone installs
// a tool. A day is long enough to keep it off the hot path and short enough that
// installing a tool is noticed the same day.
const capabilitiesTTL = 24 * time.Hour

// Capabilities is what this machine and this repository can do.
type Capabilities struct {
	SchemaVersion int    `yaml:"schema_version"`
	DetectedAt    string `yaml:"detected_at"`

	// Binaries reports which tools resolve on PATH.
	Binaries map[string]bool `yaml:"binaries"`
	// Repo reports which project markers exist in the tree.
	Repo map[string]bool `yaml:"repo"`
	// Derived is the small set of conclusions worth drawing once rather than in
	// every consumer.
	Derived CapabilityDerived `yaml:"derived"`
}

// CapabilityDerived holds conclusions drawn from the two maps above.
type CapabilityDerived struct {
	PrimaryPackageManager string   `yaml:"primary_package_manager"`
	HasContainers         bool     `yaml:"has_containers"`
	HasIAC                bool     `yaml:"has_iac"`
	HasCI                 bool     `yaml:"has_ci"`
	DetectionStack        []string `yaml:"detection_stack,flow"`
	SBOMStack             []string `yaml:"sbom_stack,flow"`
	SOAR                  string   `yaml:"soar"`
	AuthStatus            string   `yaml:"auth_status"`
}

// capabilityBinaries is every tool the skills ask about.
//
// Ordered as a list rather than a set so the file is stable across runs; the
// map it becomes is marshalled in key order by the YAML encoder.
var capabilityBinaries = []string{
	"brew", "bundler", "cargo", "composer", "cosign", "curl", "docker", "dotnet",
	"gh", "git", "go", "gradle", "grype", "helm", "jq", "kubectl", "mvn", "nix",
	"node", "npm", "nuclei", "pip", "pipx", "pnpm", "podman", "python", "python3",
	"scoop", "semgrep", "snort", "suricata", "syft", "terraform", "tofu", "trivy",
	"uv", "vulnetix", "wget", "yara", "yarn", "yq",
}

// repoMarker is one project signal and the paths that prove it.
//
// Globs rather than plain names where the marker is genuinely a family:
// `*.csproj` can sit anywhere in a .NET solution, and a workflow directory is
// only meaningful if it has something in it.
type repoMarker struct {
	key   string
	globs []string
}

var capabilityRepoMarkers = []repoMarker{
	{"cargo_toml", []string{"Cargo.toml"}},
	{"compose", []string{"compose.yml", "compose.yaml"}},
	{"composer", []string{"composer.json"}},
	{"containerfile", []string{"Containerfile", "*/Containerfile"}},
	{"csproj", []string{"*.csproj", "*/*.csproj", "*/*/*.csproj"}},
	{"docker_compose", []string{"docker-compose.yml", "docker-compose.yaml"}},
	{"dockerfile", []string{"Dockerfile", "*.dockerfile", "*/Dockerfile"}},
	{"flake_nix", []string{"flake.nix"}},
	{"gemfile_lock", []string{"Gemfile.lock"}},
	// The directory alone is not the signal: an empty .github/workflows means
	// no CI. This is the check the shell detector got wrong, which is why a
	// repository with nine workflows reported has_ci: false.
	{"gh_workflows", []string{".github/workflows/*.yml", ".github/workflows/*.yaml"}},
	{"gitlab_ci", []string{".gitlab-ci.yml"}},
	{"go_mod", []string{"go.mod"}},
	{"gradle", []string{"build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"}},
	{"package_json", []string{"package.json"}},
	{"package_lock", []string{"package-lock.json"}},
	{"pipfile_lock", []string{"Pipfile.lock"}},
	{"pnpm_lock", []string{"pnpm-lock.yaml"}},
	{"poetry_lock", []string{"poetry.lock"}},
	{"pom_xml", []string{"pom.xml"}},
	{"pyproject", []string{"pyproject.toml"}},
	{"requirements", []string{"requirements.txt", "requirements/*.txt"}},
	{"semgrep_config", []string{".semgrep.yml", ".semgrep.yaml", "semgrep.yml", "semgrep.yaml"}},
	{"snort_rules", []string{"*.rules", "rules/*.rules"}},
	{"terraform", []string{"*.tf", "*/*.tf", "terraform/*.tf"}},
	{"opentofu", []string{"*.tofu", "*/*.tofu"}},
	{"uv_lock", []string{"uv.lock"}},
	{"yara_rules_yar", []string{"*.yar", "rules/*.yar"}},
	{"yara_rules_yara", []string{"*.yara", "rules/*.yara"}},
	{"yarn_lock", []string{"yarn.lock"}},
}

// packageManagerPriority decides which ecosystem to call the primary one when a
// repository has several.
//
// Lockfiles outrank manifests, because a lockfile is what the project actually
// installs from. Within that, the order is simply which marker is the most
// specific evidence of a working build.
var packageManagerPriority = []struct {
	marker string
	name   string
}{
	{"go_mod", "go"},
	{"cargo_toml", "cargo"},
	{"pnpm_lock", "pnpm"},
	{"yarn_lock", "yarn"},
	{"package_lock", "npm"},
	{"package_json", "npm"},
	{"poetry_lock", "poetry"},
	{"uv_lock", "uv"},
	{"pipfile_lock", "pipenv"},
	{"pyproject", "python"},
	{"requirements", "pip"},
	{"gemfile_lock", "bundler"},
	{"composer", "composer"},
	{"pom_xml", "maven"},
	{"gradle", "gradle"},
	{"csproj", "dotnet"},
}

// DetectCapabilities inspects the machine and the repository.
func DetectCapabilities(root string, auth Auth) Capabilities {
	c := Capabilities{
		SchemaVersion: 1,
		DetectedAt:    time.Now().UTC().Format(time.RFC3339),
		Binaries:      make(map[string]bool, len(capabilityBinaries)),
		Repo:          make(map[string]bool, len(capabilityRepoMarkers)),
	}

	for _, name := range capabilityBinaries {
		_, err := exec.LookPath(name)
		c.Binaries[name] = err == nil
	}

	for _, m := range capabilityRepoMarkers {
		c.Repo[m.key] = anyGlobMatches(root, m.globs)
	}

	c.Derived = deriveCapabilities(c, auth)
	return c
}

// anyGlobMatches reports whether any of the patterns matches an existing file.
//
// A directory does not count. The shell detector tested for the presence of
// `.github/workflows` and concluded a repository had CI when the directory was
// empty; requiring a file makes the answer mean what its name says.
func anyGlobMatches(root string, globs []string) bool {
	for _, g := range globs {
		matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(g)))
		if err != nil {
			continue
		}
		for _, m := range matches {
			if info, err := os.Stat(m); err == nil && !info.IsDir() {
				return true
			}
		}
	}
	return false
}

func deriveCapabilities(c Capabilities, auth Auth) CapabilityDerived {
	d := CapabilityDerived{
		HasContainers: c.Repo["dockerfile"] || c.Repo["containerfile"] ||
			c.Repo["compose"] || c.Repo["docker_compose"],
		HasIAC: c.Repo["terraform"] || c.Repo["opentofu"],
		HasCI:  c.Repo["gh_workflows"] || c.Repo["gitlab_ci"],
		SOAR:   "stix",
	}

	for _, p := range packageManagerPriority {
		if c.Repo[p.marker] {
			d.PrimaryPackageManager = p.name
			break
		}
	}

	for _, tool := range []string{"nuclei", "semgrep", "yara", "snort", "suricata"} {
		if c.Binaries[tool] {
			d.DetectionStack = append(d.DetectionStack, tool)
		}
	}
	for _, tool := range []string{"syft", "grype", "trivy", "cosign"} {
		if c.Binaries[tool] {
			d.SBOMStack = append(d.SBOMStack, tool)
		}
	}

	switch {
	case auth.Missing:
		d.AuthStatus = "unauthenticated"
	case auth.Community:
		d.AuthStatus = "community"
	default:
		d.AuthStatus = "authenticated"
	}

	return d
}

// WriteCapabilities records a detection, creating .vulnetix/ if it is missing.
func WriteCapabilities(root string, c Capabilities) (string, error) {
	path := filepath.Join(root, filepath.FromSlash(CapabilitiesFile))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return path, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	// Two-space indent, matching the file the shell detector wrote. YAML does
	// not care, but skills that already grep this file with an indent-anchored
	// pattern do, and they are installed on machines this change does not reach.
	var body strings.Builder
	enc := yaml.NewEncoder(&body)
	enc.SetIndent(2)
	if err := enc.Encode(c); err != nil {
		return path, fmt.Errorf("encoding capabilities: %w", err)
	}
	if err := enc.Close(); err != nil {
		return path, fmt.Errorf("encoding capabilities: %w", err)
	}

	var b strings.Builder
	b.WriteString("# " + CapabilitiesFile + "\n")
	b.WriteString("# Written by `vulnetix agent capabilities`. Skills and hooks read this to\n")
	b.WriteString("# scope themselves to what this machine and this repository actually have.\n")
	b.WriteString("# Refreshed when older than 24h; force with --force.\n")
	b.WriteString("#\n")
	b.WriteString("# Generated. Edits are overwritten on the next refresh.\n\n")
	b.WriteString(body.String())

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return path, fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// CapabilitiesFresh reports whether a recorded detection is still within its TTL.
//
// A file that cannot be read or parsed is not fresh. Treating an unreadable
// file as current would pin a repository to a detection nobody can see.
func CapabilitiesFresh(root string) bool {
	path := filepath.Join(root, filepath.FromSlash(CapabilitiesFile))
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	var c Capabilities
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return false
	}
	at, err := time.Parse(time.RFC3339, c.DetectedAt)
	if err != nil {
		return false
	}
	return time.Since(at) < capabilitiesTTL
}

// CapabilitySummary renders the one-line-per-section view the command prints.
func CapabilitySummary(c Capabilities) string {
	var have []string
	for name, ok := range c.Binaries {
		if ok {
			have = append(have, name)
		}
	}
	sort.Strings(have)

	var markers []string
	for key, ok := range c.Repo {
		if ok {
			markers = append(markers, key)
		}
	}
	sort.Strings(markers)

	var b strings.Builder
	fmt.Fprintf(&b, "tools     %d of %d on PATH\n", len(have), len(c.Binaries))
	fmt.Fprintf(&b, "repo      %s\n", joinOr(markers, "no project markers found"))
	if c.Derived.PrimaryPackageManager != "" {
		fmt.Fprintf(&b, "packages  %s\n", c.Derived.PrimaryPackageManager)
	}
	fmt.Fprintf(&b, "auth      %s\n", c.Derived.AuthStatus)
	return b.String()
}

func joinOr(items []string, empty string) string {
	if len(items) == 0 {
		return empty
	}
	return strings.Join(items, ", ")
}
