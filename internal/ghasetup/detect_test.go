package ghasetup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-sca-match/sarif"
)

// Every tool must say when it applies, or --detect silently omits it and the
// repository that needed it gets a workflow without it.
func TestEveryToolHasADetectRule(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range c.Tools {
		d := tool.Detect
		if d.Always || d.Manual || len(d.Files) > 0 || len(d.Extensions) > 0 {
			continue
		}
		t.Errorf("%s has no detect rule: --detect will never select it and --all is the only way to get it", tool.ID)
	}
}

// The category decides which /v2/cli.<category>-sarif endpoint a report is
// filed under. A value the shared module does not recognise has no route, so
// the submission 404s.
func TestEveryToolCategoryHasARoute(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range c.Tools {
		if sarif.ParseCategory(tool.Category) == "" {
			t.Errorf("%s: category %q is not a category the ingest side accepts", tool.ID, tool.Category)
		}
	}
}

// The multi-mode tools share one SARIF driver name across several products, so
// the artifact name is the only thing that separates them. Renaming one of
// these artifacts re-files every scan it produces.
func TestMultiModeArtifactNames(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"trivy-fs":       "trivy-fs",
		"trivy-config":   "trivy-config",
		"trivy-image":    "trivy-image",
		"grype-image":    "grype-image",
		"snyk-code":      "snyk-code",
		"snyk-oss":       "snyk-oss",
		"snyk-iac":       "snyk-iac",
		"snyk-container": "snyk-container",
	}
	for id, artifact := range want {
		tool, ok := c.Find(id)
		if !ok {
			t.Errorf("catalog is missing %q", id)
			continue
		}
		if tool.Artifact != artifact {
			t.Errorf("%s: artifact is %q, must be %q or the ingest side cannot tell its scan mode apart",
				id, tool.Artifact, artifact)
		}
	}
}

// No recipe may depend on the system pip. The self-hosted pool's image ships
// python3 without it, and actions/setup-python has no build for that OS, so
// every pip-based scanner exited 1 before it scanned anything — a green job
// with no artifact, repeated across every repository, for weeks.
func TestNoRecipeDependsOnSystemPip(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range c.Tools {
		for _, s := range tool.Steps {
			if s.Uses == "actions/setup-python@v5" {
				t.Errorf("%s uses actions/setup-python, which has no build for the runner image; use astral-sh/setup-uv", tool.ID)
			}
			if s.Run != "" && (containsAll(s.Run, "pip install")) {
				t.Errorf("%s pip-installs its tool; use uvx so it does not need a system pip", tool.ID)
			}
		}
	}
}

func containsAll(haystack string, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		(func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}

			return false
		})()
}

func TestDetectPicksToolsFromTheTree(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("go.mod", "module example.com/x\n")
	write("Dockerfile", "FROM scratch\n")
	write("infra/main.tf", "resource \"null_resource\" \"a\" {}\n")
	write(".github/workflows/ci.yml", "name: ci\n")

	ids, sig, err := DetectTools(c, root)
	if err != nil {
		t.Fatal(err)
	}
	if !sig.Files["go.mod"] || !sig.Extensions[".tf"] {
		t.Fatalf("signals missed the tree: %+v", sig)
	}

	has := func(id string) bool {
		for _, got := range ids {
			if got == id {
				return true
			}
		}

		return false
	}

	for _, id := range []string{
		"gosec", "govulncheck", "golangci-lint", "cyclonedx-go", // go.mod
		"hadolint", "dockle", "trivy-image", "syft-image", // Dockerfile
		"terrascan", "tfsec", "tflint", "regula", // *.tf
		"zizmor",                      // .github/workflows
		"semgrep", "gitleaks", "syft", // always
	} {
		if !has(id) {
			t.Errorf("--detect did not select %s for a Go + Docker + Terraform repository", id)
		}
	}

	// Nothing Ruby, PHP or Swift is in this tree.
	for _, id := range []string{"brakeman", "cyclonedx-ruby", "psalm", "swiftlint", "cyclonedx-dotnet"} {
		if has(id) {
			t.Errorf("--detect selected %s for a repository with none of its files", id)
		}
	}

	// Credential- and target-gated tools are never selected automatically.
	for _, id := range []string{"snyk-code", "snyk-oss", "nuclei", "owasp-zap", "snyk-container"} {
		if has(id) {
			t.Errorf("--detect selected %s, which needs a credential or a target the repository cannot supply", id)
		}
	}
}

// node_modules and vendor carry other projects' manifests. Walking them is how
// a Go service ends up with a Ruby scanner wired into its workflow.
func TestDetectIgnoresVendoredTrees(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	for _, rel := range []string{
		"go.mod",
		"node_modules/some-dep/Gemfile",
		"vendor/other/composer.json",
		".git/config",
	} {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ids, _, err := DetectTools(c, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range ids {
		if got == "brakeman" || got == "cyclonedx-php" || got == "psalm" {
			t.Errorf("--detect selected %s from a vendored dependency's manifest", got)
		}
	}
}

// A repository with no container file must not be given the container tools.
// Hadolint is the one that used to matter: the action it wrapped wrote a
// one-byte SARIF when the Dockerfile it was pointed at did not exist, the
// artifact was uploaded anyway, and the publish job rejected it, so a run in
// which every scanner succeeded still went red.
func TestDetectSkipsContainerToolsWithoutAContainerFile(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	for _, rel := range []string{"go.mod", "main.tf", "README.md"} {
		full := filepath.Join(root, rel)
		if err := os.WriteFile(full, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	ids, _, err := DetectTools(c, root)
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range ids {
		for _, container := range []string{"hadolint", "dockle", "trivy-image", "syft-image", "grype-image"} {
			if id == container {
				t.Errorf("--detect selected %s for a repository with no Dockerfile or Containerfile", id)
			}
		}
	}

	// And the job is therefore absent from the rendered workflow, including
	// the publish job's needs list, which is what actually fails the run.
	out, err := Render(c, ids, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "\n  hadolint:\n") {
		t.Error("rendered workflow carries a hadolint job for a repository with no container file")
	}
	if strings.Contains(out, "hadolint") {
		t.Error("rendered workflow still references hadolint somewhere, including the publish needs list")
	}
}

// A container file in a subdirectory still selects hadolint, because detection
// matches basenames anywhere in the tree. The recipe therefore has to cope with
// the file not being at the root rather than writing an empty report.
func TestHadolintRecipeGuardsOnTheContainerFile(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	tool, ok := c.Find("hadolint")
	if !ok {
		t.Fatal("hadolint is not in the catalog")
	}

	var recipe string
	for _, s := range tool.Steps {
		recipe += s.Run
		if s.Uses != "" {
			t.Errorf("hadolint step uses the action %q, which cannot be skipped when no container file exists", s.Uses)
		}
	}

	for _, want := range []string{
		"::notice::no Dockerfile or Containerfile found",
		"exit 0",
		"rm -f hadolint.sarif",
	} {
		if !strings.Contains(recipe, want) {
			t.Errorf("hadolint recipe is missing %q", want)
		}
	}
	if !strings.Contains(recipe, "Containerfile") {
		t.Error("hadolint recipe never looks for a Containerfile")
	}
}
