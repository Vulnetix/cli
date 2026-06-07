package fix

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScopedJSONOnlyEditsDependencyBlock(t *testing.T) {
	content := `{
  "name": "left-pad",
  "dependencies": {
    "left-pad": "^1.1.0"
  },
  "overrides": {
    "left-pad": "1.0.0"
  }
}`
	next, changed := editManifest(content, FixCandidate{
		PackageName: "left-pad",
		SourceFile:  "package.json",
		TargetVer:   "1.3.0",
	})
	require.True(t, changed)
	require.Contains(t, next, `"left-pad": "^1.3.0"`) // dependencies bumped
	require.Contains(t, next, `"left-pad": "1.0.0"`)  // overrides untouched
	require.Contains(t, next, `"name": "left-pad"`)   // package name untouched
}

func TestComposerRequireBlockEdited(t *testing.T) {
	content := `{
  "require": {
    "monolog/monolog": "^1.0"
  }
}`
	next, changed := editManifest(content, FixCandidate{
		PackageName: "monolog/monolog",
		SourceFile:  "composer.json",
		TargetVer:   "1.27.1",
	})
	require.True(t, changed)
	require.Contains(t, next, `"monolog/monolog": "^1.27.1"`)
}

func TestPomXMLVersionBump(t *testing.T) {
	content := `<project>
  <dependencies>
    <dependency>
      <groupId>org.yaml</groupId>
      <artifactId>snakeyaml</artifactId>
      <version>1.30</version>
    </dependency>
  </dependencies>
</project>`
	next, changed := editManifest(content, FixCandidate{
		PackageName: "org.yaml:snakeyaml",
		SourceFile:  "pom.xml",
		TargetVer:   "2.2",
	})
	require.True(t, changed)
	require.Contains(t, next, "<version>2.2</version>")
}

func TestPomXMLLeavesPropertyVersionsAlone(t *testing.T) {
	content := `<project>
  <dependencies>
    <dependency>
      <artifactId>snakeyaml</artifactId>
      <version>${snakeyaml.version}</version>
    </dependency>
  </dependencies>
</project>`
	_, changed := editManifest(content, FixCandidate{
		PackageName: "snakeyaml",
		SourceFile:  "pom.xml",
		TargetVer:   "2.2",
	})
	require.False(t, changed)
}

func TestPyprojectPoetryTable(t *testing.T) {
	content := "[tool.poetry.dependencies]\nflask = \"^1.0\"\n"
	next, changed := editManifest(content, FixCandidate{
		PackageName: "flask",
		SourceFile:  "pyproject.toml",
		TargetVer:   "2.0.1",
	})
	require.True(t, changed)
	require.Contains(t, next, `flask = "^2.0.1"`)
}

func TestPyprojectPEP621Array(t *testing.T) {
	content := "[project]\ndependencies = [\n  \"flask>=1.0\",\n  \"requests\",\n]\n"
	next, changed := editManifest(content, FixCandidate{
		PackageName: "flask",
		SourceFile:  "pyproject.toml",
		TargetVer:   "2.0.1",
	})
	require.True(t, changed)
	require.Contains(t, next, `"flask==2.0.1"`)
}

func TestRequirementsPinsBareDependency(t *testing.T) {
	content := "flask\nrequests==2.0\n"
	next, changed := editManifest(content, FixCandidate{
		PackageName: "flask",
		SourceFile:  "requirements.txt",
		TargetVer:   "2.0.1",
	})
	require.True(t, changed)
	require.Contains(t, next, "flask==2.0.1")
	require.Contains(t, next, "requests==2.0")
}

func TestApplyOverrideWritesEcosystemStyle(t *testing.T) {
	cases := []struct {
		pm       string
		contains string
	}{
		{"npm", `"overrides"`},
		{"bun", `"overrides"`},
		{"pnpm", `"pnpm"`},
		{"yarn", `"resolutions"`},
	}
	for _, tc := range cases {
		t.Run(tc.pm, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"app","dependencies":{"app-dep":"^1.0.0"}}`), 0o644))
			err := ApplyOverride(dir, FixCandidate{
				PackageName:    "nested-vuln",
				Ecosystem:      "npm",
				SourceFile:     "package.json",
				TargetVer:      "4.17.21",
				Method:         MethodOverride,
				PackageManager: tc.pm,
			})
			require.NoError(t, err)
			out, err := os.ReadFile(filepath.Join(dir, "package.json"))
			require.NoError(t, err)
			require.Contains(t, string(out), tc.contains)
			require.Contains(t, string(out), "4.17.21")
			require.Contains(t, string(out), "nested-vuln")
		})
	}
}

func TestParentUpgradeEditsDirectParentRange(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies": {"parent": "^1.0.0"}}`), 0o644))
	err := Apply(dir, []FixCandidate{{
		PackageName:  "child",
		Ecosystem:    "npm",
		SourceFile:   "package.json",
		TargetVer:    "2.2.3",
		Method:       MethodParentUpgrade,
		ParentName:   "parent",
		ParentTarget: "2.0.0",
	}})
	require.NoError(t, err)
	out, err := os.ReadFile(filepath.Join(dir, "package.json"))
	require.NoError(t, err)
	require.Contains(t, string(out), `"parent": "^2.0.0"`)
}
