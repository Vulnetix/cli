package fix

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnsureRequirementPinnedAppendsWhenAbsent(t *testing.T) {
	// Transitive child not present in requirements.txt → append a hard pin.
	next, ok := ensureRequirementPinned("flask==2.0\n", "urllib3", "1.26.18")
	require.True(t, ok)
	require.Contains(t, next, "flask==2.0")
	require.Contains(t, next, "urllib3==1.26.18")
}

func TestEnsureRequirementPinnedReplacesWhenPresent(t *testing.T) {
	next, ok := ensureRequirementPinned("urllib3==1.25.0\n", "urllib3", "1.26.18")
	require.True(t, ok)
	require.Contains(t, next, "urllib3==1.26.18")
	require.NotContains(t, next, "1.25.0")
}

func TestEnsureMavenManagedCreatesSection(t *testing.T) {
	content := "<project>\n  <dependencies>\n  </dependencies>\n</project>\n"
	next, ok := ensureMavenManaged(content, "com.fasterxml.jackson.core:jackson-databind", "2.15.0")
	require.True(t, ok)
	require.Contains(t, next, "<dependencyManagement>")
	require.Contains(t, next, "<artifactId>jackson-databind</artifactId>")
	require.Contains(t, next, "<version>2.15.0</version>")
}

func TestEnsureMavenManagedInsertsIntoExistingSection(t *testing.T) {
	content := "<project>\n  <dependencyManagement>\n    <dependencies>\n    </dependencies>\n  </dependencyManagement>\n</project>\n"
	next, ok := ensureMavenManaged(content, "org.yaml:snakeyaml", "2.2")
	require.True(t, ok)
	// Exactly one dependencyManagement section (no duplicate created).
	require.Equal(t, 1, countSubstr(next, "<dependencyManagement>"))
	require.Contains(t, next, "<artifactId>snakeyaml</artifactId>")
}

func TestEnsureComposerRequireAddsTransitive(t *testing.T) {
	next, ok := ensureComposerRequire(`{"require":{"php":">=8.0"}}`, "guzzlehttp/psr7", "2.5.0")
	require.True(t, ok)
	require.Contains(t, next, "guzzlehttp/psr7")
	require.Contains(t, next, "2.5.0")
}

func TestEnsureGemfilePinnedAppendsWhenAbsent(t *testing.T) {
	next, ok := ensureGemfilePinned("source \"https://rubygems.org\"\ngem \"rails\"\n", "nokogiri", "1.16.5")
	require.True(t, ok)
	require.Contains(t, next, `gem "nokogiri", "1.16.5"`)
}

// End-to-end: Apply() writes the per-ecosystem pin for a transitive override.
func TestApplyOverridePinsTransitiveAcrossEcosystems(t *testing.T) {
	t.Run("pypi-append", func(t *testing.T) {
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("flask==2.0\n"), 0o644))
		require.NoError(t, Apply(dir, []FixCandidate{{
			PackageName: "urllib3", Ecosystem: "pypi", SourceFile: "requirements.txt",
			TargetVer: "1.26.18", Method: MethodOverride,
		}}))
		out, _ := os.ReadFile(filepath.Join(dir, "requirements.txt"))
		require.Contains(t, string(out), "urllib3==1.26.18")
	})
	t.Run("go-no-edit", func(t *testing.T) {
		// go pins via the install command, not a manifest edit; Apply must not error.
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o644))
		require.NoError(t, Apply(dir, []FixCandidate{{
			PackageName: "golang.org/x/net", Ecosystem: "golang", SourceFile: "go.mod",
			TargetVer: "0.23.0", Method: MethodOverride,
		}}))
	})
}

func countSubstr(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}
